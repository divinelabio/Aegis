package licensing

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/divinelab-io/aegis/internal/edition"
)

type Config struct {
	StateDir         string
	APIURL           string
	Issuer           string
	Audience         string
	Version          string
	CompiledTier     edition.BuildTier
	CompiledFeatures edition.FeatureSet
	TrustedKeys      map[string]ed25519.PublicKey
	RefreshInterval  time.Duration
	Clock            func() time.Time
}

// StaticTrustedKeys parses kid=base64-public-key entries supplied by an
// official build. Private or symmetric signing material is never embedded.
func StaticTrustedKeys(values map[string]string) (map[string]ed25519.PublicKey, error) {
	keys := make(map[string]ed25519.PublicKey, len(values))
	for kid, encoded := range values {
		decoded, err := base64.RawStdEncoding.DecodeString(encoded)
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid trusted key %q", kid)
		}
		keys[kid] = ed25519.PublicKey(decoded)
	}
	return keys, nil
}

type RuntimeManager struct {
	config   Config
	identity installationIdentity
	client   *apiClient
	verifier verifier

	stateMu sync.Mutex
	state   persistedState
	current atomic.Value // Snapshot

	subscribersMu sync.Mutex
	subscribers   []chan Snapshot
}

const maxLocalClockRollback = 2 * time.Minute

func NewManager(config Config) (*RuntimeManager, error) {
	if config.StateDir == "" {
		config.StateDir = "./data/license"
	}
	if config.Issuer == "" {
		config.Issuer = "https://license.divinelab.io"
	}
	if config.Audience == "" {
		config.Audience = "aegis-runtime"
	}
	if config.RefreshInterval <= 0 {
		config.RefreshInterval = 6 * time.Hour
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if !config.CompiledTier.Valid() {
		config.CompiledTier = edition.CommunityTier
	}
	if config.CompiledFeatures == nil {
		config.CompiledFeatures = edition.FeaturesForTier(config.CompiledTier)
	}
	identity, err := loadOrCreateIdentity(config.StateDir)
	if err != nil {
		return nil, fmt.Errorf("load installation identity: %w", err)
	}
	state, stateErr := loadPersistedState(config.StateDir)
	manager := &RuntimeManager{
		config:   config,
		identity: identity,
		state:    state,
		verifier: verifier{issuer: config.Issuer, audience: config.Audience, keys: config.TrustedKeys, clock: config.Clock},
	}
	if config.APIURL != "" {
		manager.client, err = newAPIClient(config.APIURL)
		if err != nil {
			return nil, err
		}
	}
	manager.current.Store(manager.communitySnapshot())
	if stateErr != nil {
		snapshot := manager.communitySnapshot()
		snapshot.Status = StatusInvalid
		snapshot.LastError = "stored licence state is unreadable"
		manager.current.Store(snapshot)
		return manager, nil
	}
	if state.Entitlement != "" {
		if err := manager.applyEntitlement(state.Entitlement, state.LastServerTime, UpgradeInfo{}); err != nil {
			snapshot := manager.communitySnapshot()
			snapshot.Status = StatusInvalid
			snapshot.LastError = err.Error()
			manager.current.Store(snapshot)
		} else if err := manager.recordObservedTime(config.Clock().UTC()); err != nil {
			snapshot := manager.communitySnapshot()
			snapshot.Status = StatusInvalid
			snapshot.LastError = fmt.Sprintf("persist licence trusted time: %v", err)
			manager.current.Store(snapshot)
		}
	}
	return manager, nil
}

func (m *RuntimeManager) Snapshot() Snapshot {
	snapshot := m.current.Load().(Snapshot)
	snapshot.Features = append([]edition.FeatureID(nil), snapshot.Features...)
	snapshot.effective = snapshot.effective.Clone()
	return snapshot
}

func (m *RuntimeManager) Has(feature edition.FeatureID) bool {
	return m.current.Load().(Snapshot).Has(feature)
}

func (m *RuntimeManager) Subscribe() <-chan Snapshot {
	channel := make(chan Snapshot, 1)
	channel <- m.Snapshot()
	m.subscribersMu.Lock()
	m.subscribers = append(m.subscribers, channel)
	m.subscribersMu.Unlock()
	return channel
}

func (m *RuntimeManager) Activate(ctx context.Context, key string) (ActivationResult, error) {
	if m.client == nil {
		return ActivationResult{}, errors.New("licence activation service is not configured")
	}
	if key == "" {
		return ActivationResult{}, errors.New("licence key is required")
	}
	m.publish(m.withStatus(StatusActivating, ""))
	nonce, err := randomNonce()
	if err != nil {
		return ActivationResult{}, err
	}
	response, err := m.client.activate(ctx, activationRequest{
		LicenseKey:     key,
		InstallationID: m.identity.InstallationID,
		PublicKey:      base64.RawStdEncoding.EncodeToString(m.identity.PublicKey),
		Platform:       platformName(),
		Architecture:   architectureName(),
		Version:        m.config.Version,
		Nonce:          nonce,
	})
	if err != nil {
		m.publish(m.withStatus(StatusCommunity, err.Error()))
		return ActivationResult{}, err
	}
	if response.ActivationID == "" {
		return ActivationResult{}, errors.New("licence activation response is missing an activation ID")
	}
	upgrade, err := m.upgradeFromResponse(response)
	if err != nil {
		return ActivationResult{}, err
	}
	now := m.config.Clock().UTC()
	m.stateMu.Lock()
	previousServerTime := m.state.LastServerTime
	m.stateMu.Unlock()
	snapshot, err := m.entitlementSnapshot(response.Entitlement, response.ServerTime, previousServerTime, now, upgrade, response.ActivationID)
	if err != nil {
		m.publish(m.withStatus(StatusInvalid, err.Error()))
		return ActivationResult{}, err
	}
	candidate := persistedState{
		ActivationID:   response.ActivationID,
		Entitlement:    response.Entitlement,
		LastServerTime: response.ServerTime.UTC(),
		LastObservedAt: now,
		LastRefresh:    now,
	}
	if err := savePersistedState(m.config.StateDir, candidate); err != nil {
		return ActivationResult{}, err
	}
	m.stateMu.Lock()
	m.state = candidate
	m.stateMu.Unlock()
	m.publish(snapshot)
	return ActivationResult{Snapshot: m.Snapshot(), Upgrade: upgrade}, nil
}

func (m *RuntimeManager) Refresh(ctx context.Context) error {
	if m.client == nil {
		return errors.New("licence activation service is not configured")
	}
	m.stateMu.Lock()
	activationID := m.state.ActivationID
	m.stateMu.Unlock()
	if activationID == "" {
		return errors.New("installation is not activated")
	}
	nonce, err := randomNonce()
	if err != nil {
		return err
	}
	response, err := m.client.refresh(ctx, activationID, leaseRequest{
		ActivationID:   activationID,
		InstallationID: m.identity.InstallationID,
		RuntimeID:      m.identity.RuntimeID,
		Version:        m.config.Version,
		Timestamp:      m.config.Clock().UTC().Unix(),
		Nonce:          nonce,
	}, m.identity.PrivateKey)
	if err != nil {
		m.recalculateCached(err.Error())
		return err
	}
	if response.ActivationID != "" && response.ActivationID != activationID {
		return errors.New("licence refresh response activation ID does not match the active installation")
	}
	upgrade, err := m.upgradeFromResponse(response)
	if err != nil {
		return err
	}
	now := m.config.Clock().UTC()
	m.stateMu.Lock()
	previousServerTime := m.state.LastServerTime
	candidate := m.state
	m.stateMu.Unlock()
	snapshot, err := m.entitlementSnapshot(response.Entitlement, response.ServerTime, previousServerTime, now, upgrade, activationID)
	if err != nil {
		return err
	}
	candidate.Entitlement = response.Entitlement
	candidate.LastServerTime = response.ServerTime.UTC()
	candidate.LastObservedAt = now
	candidate.LastRefresh = now
	if err := savePersistedState(m.config.StateDir, candidate); err != nil {
		return err
	}
	m.stateMu.Lock()
	m.state = candidate
	m.stateMu.Unlock()
	m.publish(snapshot)
	return nil
}

func (m *RuntimeManager) Deactivate(ctx context.Context) error {
	if m.client == nil {
		return errors.New("licence activation service is not configured")
	}
	m.stateMu.Lock()
	activationID := m.state.ActivationID
	m.stateMu.Unlock()
	if activationID == "" {
		return nil
	}
	nonce, err := randomNonce()
	if err != nil {
		return err
	}
	err = m.client.deactivate(ctx, activationID, leaseRequest{
		ActivationID:   activationID,
		InstallationID: m.identity.InstallationID,
		RuntimeID:      m.identity.RuntimeID,
		Version:        m.config.Version,
		Timestamp:      m.config.Clock().UTC().Unix(),
		Nonce:          nonce,
	}, m.identity.PrivateKey)
	if err != nil {
		m.publish(m.withStatus(StatusDeactivationPending, err.Error()))
		return err
	}
	m.stateMu.Lock()
	m.state = persistedState{}
	m.stateMu.Unlock()
	if err := clearPersistedState(m.config.StateDir); err != nil {
		return err
	}
	m.publish(m.communitySnapshot())
	return nil
}

func (m *RuntimeManager) Start(ctx context.Context) {
	if m.client == nil {
		return
	}
	go func() {
		for {
			jitter := time.Duration(rand.Int63n(int64(m.config.RefreshInterval / 5)))
			timer := time.NewTimer(m.config.RefreshInterval + jitter)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
				refreshCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
				_ = m.Refresh(refreshCtx)
				cancel()
			}
		}
	}()
}

func (m *RuntimeManager) applyEntitlement(raw string, serverTime time.Time, upgrade UpgradeInfo) error {
	m.stateMu.Lock()
	previousServerTime := m.state.LastServerTime
	lastRefresh := m.state.LastRefresh
	activationID := m.state.ActivationID
	m.stateMu.Unlock()
	snapshot, err := m.entitlementSnapshot(raw, serverTime, previousServerTime, lastRefresh, upgrade, activationID)
	if err != nil {
		return err
	}
	m.publish(snapshot)
	return nil
}

func (m *RuntimeManager) entitlementSnapshot(raw string, serverTime, previousServerTime, lastRefresh time.Time, upgrade UpgradeInfo, expectedActivationID string) (Snapshot, error) {
	if !serverTime.IsZero() && !previousServerTime.IsZero() && serverTime.Before(previousServerTime.Add(-2*time.Minute)) {
		return Snapshot{}, errors.New("licence server time moved backwards")
	}
	claims, err := m.verifier.verify(raw, publicKeyHash(m.identity.PublicKey))
	if err != nil {
		return Snapshot{}, err
	}
	if expectedActivationID != "" && claims.ActivationID != expectedActivationID {
		return Snapshot{}, errors.New("entitlement activation ID does not match the active installation")
	}
	now := m.config.Clock().UTC()
	m.stateMu.Lock()
	lastObservedAt := m.state.LastObservedAt
	m.stateMu.Unlock()
	if !lastObservedAt.IsZero() && now.Add(maxLocalClockRollback).Before(lastObservedAt) {
		return Snapshot{}, errors.New("local clock moved backwards; restore the correct system time and refresh the licence")
	}
	status := claims.LicenseStatus
	if status == "" {
		status = StatusActive
	}
	paidAllowed := status != StatusSuspended && status != StatusRevoked && status != StatusExpired && status != StatusInvalid
	if now.After(claims.OfflineUntil.Time) {
		status = StatusExpired
		paidAllowed = false
	} else if now.After(claims.ExpiresAt.Time) && paidAllowed {
		status = StatusGrace
	}

	entitled := edition.FeaturesForTier(edition.CommunityTier)
	if paidAllowed {
		for _, feature := range claims.Features {
			entitled[feature] = struct{}{}
		}
	}
	effective := edition.Intersect(m.config.CompiledFeatures, entitled)
	effectiveTier := edition.CommunityTier
	if paidAllowed {
		effectiveTier = claims.Tier
		if effectiveTier.Rank() > m.config.CompiledTier.Rank() {
			effectiveTier = m.config.CompiledTier
			status = StatusUpgradeRequired
			upgrade.Required = true
			upgrade.TargetTier = claims.Tier
		}
	}
	snapshot := Snapshot{
		BuildTier:     m.config.CompiledTier,
		LicensedTier:  claims.Tier,
		EffectiveTier: effectiveTier,
		Status:        status,
		Features:      effective.Sorted(),
		ActivationID:  claims.ActivationID,
		ExpiresAt:     claims.ExpiresAt.Time,
		OfflineUntil:  claims.OfflineUntil.Time,
		LastRefresh:   lastRefresh,
		Upgrade:       upgrade,
		effective:     effective,
	}
	if claims.SubscriptionEnd != nil {
		snapshot.SubscriptionEnd = claims.SubscriptionEnd.Time
	}
	return snapshot, nil
}

func (m *RuntimeManager) recalculateCached(message string) {
	m.stateMu.Lock()
	raw := m.state.Entitlement
	serverTime := m.state.LastServerTime
	m.stateMu.Unlock()
	if raw == "" {
		m.publish(m.withStatus(StatusCommunity, message))
		return
	}
	if err := m.applyEntitlement(raw, serverTime, m.Snapshot().Upgrade); err != nil {
		snapshot := m.communitySnapshot()
		snapshot.Status = StatusInvalid
		snapshot.LastError = err.Error()
		m.publish(snapshot)
		return
	}
	if err := m.recordObservedTime(m.config.Clock().UTC()); err != nil {
		snapshot := m.communitySnapshot()
		snapshot.Status = StatusInvalid
		snapshot.LastError = fmt.Sprintf("persist licence trusted time: %v", err)
		m.publish(snapshot)
		return
	}
	snapshot := m.Snapshot()
	snapshot.LastError = message
	m.publish(snapshot)
}

// recordObservedTime advances the persisted local-time watermark without ever
// lowering it. A cached entitlement is therefore not reusable after a
// meaningful wall-clock rollback on a later restart.
func (m *RuntimeManager) recordObservedTime(now time.Time) error {
	now = now.UTC()
	m.stateMu.Lock()
	candidate := m.state
	if candidate.LastObservedAt.After(now) {
		now = candidate.LastObservedAt
	}
	candidate.LastObservedAt = now
	m.stateMu.Unlock()
	if err := savePersistedState(m.config.StateDir, candidate); err != nil {
		return err
	}
	m.stateMu.Lock()
	m.state = candidate
	m.stateMu.Unlock()
	return nil
}

func (m *RuntimeManager) communitySnapshot() Snapshot {
	effective := edition.Intersect(m.config.CompiledFeatures, edition.FeaturesForTier(edition.CommunityTier))
	return Snapshot{
		BuildTier:     m.config.CompiledTier,
		LicensedTier:  edition.CommunityTier,
		EffectiveTier: edition.CommunityTier,
		Status:        StatusCommunity,
		Features:      effective.Sorted(),
		effective:     effective,
	}
}

func (m *RuntimeManager) withStatus(status Status, message string) Snapshot {
	snapshot := m.Snapshot()
	snapshot.Status = status
	snapshot.LastError = message
	return snapshot
}

func (m *RuntimeManager) publish(snapshot Snapshot) {
	m.current.Store(snapshot)
	m.subscribersMu.Lock()
	defer m.subscribersMu.Unlock()
	for _, subscriber := range m.subscribers {
		select {
		case subscriber <- snapshot:
		default:
			select {
			case <-subscriber:
			default:
			}
			select {
			case subscriber <- snapshot:
			default:
			}
		}
	}
}

func (m *RuntimeManager) upgradeFromResponse(response apiResponse) (UpgradeInfo, error) {
	upgrade := UpgradeInfo{
		TargetVersion: response.TargetVersion,
		Manifest:      response.ArtifactManifest,
		Credential:    response.ArtifactCredential,
	}
	if response.TargetTier == "" {
		return upgrade, nil
	}
	tier, err := edition.ParseBuildTier(response.TargetTier)
	if err != nil {
		return UpgradeInfo{}, err
	}
	upgrade.TargetTier = tier
	upgrade.Required = tier.Rank() > m.config.CompiledTier.Rank()
	if upgrade.Required {
		upgrade.State = "ready"
	}
	return upgrade, nil
}
