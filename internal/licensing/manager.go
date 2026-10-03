package licensing

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/divinelabio/aegis/internal/edition"
	"golang.org/x/mod/semver"
)

type Config struct {
	StateDir           string
	APIURL             string
	Issuer             string
	Audience           string
	Version            string
	ArtifactFormat     string
	UpdaterVersion     string
	UpdaterVersionFunc func(context.Context) string
	CompiledTier       edition.BuildTier
	CompiledFeatures   edition.FeatureSet
	TrustedKeys        map[string]ed25519.PublicKey
	RootPublicKey      string
	SignedKeySet       string
	RefreshInterval    time.Duration
	Clock              func() time.Time
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
	operationMu sync.Mutex
	config      Config
	identity    installationIdentity
	client      *apiClient
	verifier    verifier

	stateMu sync.Mutex
	state   persistedState
	current atomic.Value // Snapshot

	subscribersMu sync.Mutex
	subscribers   []chan Snapshot
}

const maxLocalClockRollback = 2 * time.Minute

func NewManager(config Config) (*RuntimeManager, error) {
	if config.ArtifactFormat == "" {
		config.ArtifactFormat = "tar.gz"
		if platformName() == "windows" {
			config.ArtifactFormat = "zip"
		}
	}
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
		config.RefreshInterval = 5 * time.Minute
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
	if state.SignedKeySet != "" {
		// A newer official binary may carry a newer certified bundle than the
		// installation last persisted. Keep the compiled bundle in that case;
		// restoring the old one would both roll trust back and block startup.
		useStored := true
		if config.SignedKeySet != "" {
			storedVersion, storedErr := CertifiedKeySetVersion(state.SignedKeySet)
			compiledVersion, compiledErr := CertifiedKeySetVersion(config.SignedKeySet)
			if storedErr == nil && compiledErr == nil && storedVersion < compiledVersion {
				useStored = false
			}
		}
		if useStored {
			if err := manager.acceptKeySet(state.SignedKeySet); err != nil {
				return nil, fmt.Errorf("restore certified trust: %w", err)
			}
		}
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
		upgrade, _ := manager.upgradeFromResponse(apiResponse{TargetTier: state.Upgrade.TargetTier, TargetVersion: state.Upgrade.TargetVersion, ArtifactManifest: state.Upgrade.Manifest, ArtifactStatus: state.Upgrade.ArtifactStatus, ArtifactMinimumUpdaterVersion: state.Upgrade.MinimumUpdaterVersion})
		if err := manager.applyEntitlement(state.Entitlement, state.LastServerTime, upgrade); err != nil {
			snapshot := manager.communitySnapshot()
			snapshot.ActivationID = state.ActivationID
			snapshot.Status = StatusInvalid
			snapshot.LastError = err.Error()
			manager.current.Store(snapshot)
		} else if err := manager.recordObservedTime(config.Clock().UTC()); err != nil {
			snapshot := manager.communitySnapshot()
			snapshot.ActivationID = state.ActivationID
			snapshot.Status = StatusInvalid
			snapshot.LastError = fmt.Sprintf("persist licence trusted time: %v", err)
			manager.current.Store(snapshot)
		}
	}
	return manager, nil
}

func (m *RuntimeManager) Snapshot() Snapshot {
	snapshot := m.current.Load().(Snapshot)
	paidStatus := snapshot.Status == StatusActive || snapshot.Status == StatusGrace || snapshot.Status == StatusPastDue || snapshot.Status == StatusUpgradeRequired
	if paidStatus && !snapshot.OfflineUntil.IsZero() && !m.config.Clock().Before(snapshot.OfflineUntil) {
		snapshot.Status = StatusExpired
		snapshot.EffectiveTier = edition.CommunityTier
		snapshot.effective = edition.Intersect(m.config.CompiledFeatures, edition.FeaturesForTier(edition.CommunityTier))
		snapshot.Features = snapshot.effective.Sorted()
		snapshot.Upgrade = UpgradeInfo{}
	} else if !snapshot.ExpiresAt.IsZero() && !m.config.Clock().Before(snapshot.ExpiresAt) && snapshot.Status == StatusActive {
		snapshot.Status = StatusGrace
	}
	snapshot.Features = append([]edition.FeatureID(nil), snapshot.Features...)
	if snapshot.Upgrade.Available && !snapshot.Upgrade.ValidUntil.IsZero() && !m.config.Clock().Before(snapshot.Upgrade.ValidUntil) {
		snapshot.Upgrade.Available = false
		snapshot.Upgrade.State = "unavailable"
		snapshot.Upgrade.Reason = "The release manifest expired. Refresh to obtain a current release manifest."
	}
	snapshot.effective = snapshot.effective.Clone()
	return snapshot
}

func (m *RuntimeManager) Has(feature edition.FeatureID) bool {
	return m.Snapshot().Has(feature)
}

func (m *RuntimeManager) Subscribe() <-chan Snapshot {
	channel := make(chan Snapshot, 1)
	channel <- m.Snapshot()
	m.subscribersMu.Lock()
	m.subscribers = append(m.subscribers, channel)
	m.subscribersMu.Unlock()
	return channel
}

func (m *RuntimeManager) Activate(ctx context.Context, key string) (result ActivationResult, activationErr error) {
	m.operationMu.Lock()
	defer m.operationMu.Unlock()
	previous := m.Snapshot()
	committed := false
	defer func() {
		if !committed {
			m.publish(previous)
		}
	}()
	m.stateMu.Lock()
	oldActivation := m.state.ActivationID
	m.stateMu.Unlock()
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
		RuntimeID:      m.identity.RuntimeID,
		Platform:       platformName(),
		Architecture:   architectureName(),
		Version:        m.config.Version,
		Nonce:          nonce,
		ArtifactFormat: m.config.ArtifactFormat,
		UpdaterVersion: m.updaterVersion(ctx),
	})
	if err != nil {
		m.publish(m.withStatus(StatusCommunity, err.Error()))
		return ActivationResult{}, err
	}
	if response.ActivationID == "" {
		return ActivationResult{}, errors.New("licence activation response is missing an activation ID")
	}
	// Release the reserved seat if validation or local persistence fails.
	defer func() {
		if committed || response.ActivationID == oldActivation {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// Journal before DELETE so a failed or ambiguous response can be retried
		// after restart without overwriting the previously valid entitlement.
		if err := m.queueActivationRelease(response.ActivationID); err != nil {
			activationErr = errors.Join(activationErr, fmt.Errorf("persist rejected activation cleanup: %w", err), m.releaseActivation(cleanupCtx, response.ActivationID))
			return
		}
		activationErr = errors.Join(activationErr, m.releasePendingActivations(cleanupCtx))
	}()
	if response.ActivationID != oldActivation {
		if err := m.queueActivationRelease(response.ActivationID); err != nil {
			return ActivationResult{}, fmt.Errorf("persist activation reservation: %w", err)
		}
	}
	if err := m.acceptKeySet(response.SignedKeySet); err != nil {
		return ActivationResult{}, err
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
	if oldActivation != "" && snapshot.Status != StatusActive && snapshot.Status != StatusGrace && snapshot.Status != StatusPastDue && snapshot.Status != StatusUpgradeRequired {
		return ActivationResult{}, errors.New("replacement licence does not grant a usable entitlement")
	}
	m.stateMu.Lock()
	pending := append([]string(nil), m.state.PendingDeactivations...)
	m.stateMu.Unlock()
	candidate := persistedState{
		ActivationID:         response.ActivationID,
		Entitlement:          response.Entitlement,
		LastServerTime:       response.ServerTime.UTC(),
		LastObservedAt:       now,
		LastRefresh:          now,
		Upgrade:              storedUpgrade{TargetTier: string(upgrade.TargetTier), TargetVersion: upgrade.TargetVersion, Manifest: upgrade.Manifest, ArtifactStatus: response.ArtifactStatus, MinimumUpdaterVersion: upgrade.MinimumUpdaterVersion},
		SignedKeySet:         m.config.SignedKeySet,
		PendingDeactivations: pending,
	}
	candidate.PendingDeactivations = pendingActivationReleases(candidate, oldActivation)
	var persistenceErr error
	if err := savePersistedState(m.config.StateDir, candidate); err != nil {
		// writeJSONAtomic can report a permission-hardening error after rename.
		// Never release a new seat if its entitlement is already on disk.
		stored, readErr := loadPersistedState(m.config.StateDir)
		if readErr != nil || stored.ActivationID != candidate.ActivationID || stored.Entitlement != candidate.Entitlement {
			return ActivationResult{}, err
		}
		persistenceErr = fmt.Errorf("secure committed licence state: %w", err)
	}
	m.stateMu.Lock()
	m.state = candidate
	m.stateMu.Unlock()
	m.publish(snapshot)
	committed = true
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := m.releasePendingActivations(cleanupCtx); err != nil {
		m.publish(m.withStatus(snapshot.Status, "Previous licence seat release is pending: "+err.Error()))
	}
	return ActivationResult{Snapshot: m.Snapshot(), Upgrade: snapshot.Upgrade}, persistenceErr
}

func (m *RuntimeManager) Refresh(ctx context.Context) error {
	m.operationMu.Lock()
	defer m.operationMu.Unlock()
	return m.refresh(ctx)
}

func (m *RuntimeManager) refresh(ctx context.Context) (operationErr error) {
	cleanupErr := m.releasePendingActivations(ctx)
	defer func() {
		if operationErr != nil {
			m.recalculateCached(operationErr.Error())
		} else if cleanupErr != nil {
			m.publish(m.withStatus(m.Snapshot().Status, "Previous licence seat release is pending: "+cleanupErr.Error()))
		}
	}()
	if m.client == nil {
		return errors.New("licence activation service is not configured")
	}
	m.stateMu.Lock()
	activationID := m.state.ActivationID
	m.stateMu.Unlock()
	if activationID == "" {
		if cleanupErr != nil {
			return cleanupErr
		}
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
		ArtifactFormat: m.config.ArtifactFormat,
		UpdaterVersion: m.updaterVersion(ctx),
	}, m.identity.PrivateKey)
	if err != nil {
		return err
	}
	if response.ActivationID != "" && response.ActivationID != activationID {
		return errors.New("licence refresh response activation ID does not match the active installation")
	}
	if err := m.acceptKeySet(response.SignedKeySet); err != nil {
		return err
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
	candidate.Upgrade = storedUpgrade{TargetTier: string(upgrade.TargetTier), TargetVersion: upgrade.TargetVersion, Manifest: upgrade.Manifest, ArtifactStatus: response.ArtifactStatus, MinimumUpdaterVersion: upgrade.MinimumUpdaterVersion}
	candidate.SignedKeySet = m.config.SignedKeySet
	if err := savePersistedState(m.config.StateDir, candidate); err != nil {
		return err
	}
	m.stateMu.Lock()
	m.state = candidate
	m.stateMu.Unlock()
	m.publish(snapshot)
	return nil
}

func (m *RuntimeManager) updaterVersion(ctx context.Context) string {
	if m.config.UpdaterVersionFunc != nil {
		return m.config.UpdaterVersionFunc(ctx)
	}
	return m.config.UpdaterVersion
}

func (m *RuntimeManager) acceptKeySet(encoded string) error {
	if encoded == "" || encoded == m.config.SignedKeySet {
		return nil
	}
	if m.config.RootPublicKey == "" {
		return errors.New("a root-certified key set cannot be accepted without the pinned root key")
	}
	keys, err := CertifiedTrustedKeys(m.config.RootPublicKey, encoded, KeyPurposeLease, m.config.Clock())
	if err != nil {
		return err
	}
	version, err := CertifiedKeySetVersion(encoded)
	if err != nil {
		return err
	}
	if m.config.SignedKeySet != "" {
		previous, err := CertifiedKeySetVersion(m.config.SignedKeySet)
		if err != nil {
			return err
		}
		if version <= previous {
			return errors.New("certified key set downgrade rejected")
		}
	}
	m.verifier.keys = keys
	m.config.SignedKeySet = encoded
	return nil
}

func (m *RuntimeManager) Deactivate(ctx context.Context) error {
	m.operationMu.Lock()
	defer m.operationMu.Unlock()
	if m.client == nil {
		return errors.New("licence activation service is not configured")
	}
	m.stateMu.Lock()
	activationID := m.state.ActivationID
	m.stateMu.Unlock()
	if activationID == "" {
		return m.releasePendingActivations(ctx)
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
	pending := append([]string(nil), m.state.PendingDeactivations...)
	m.stateMu.Unlock()
	candidate := persistedState{PendingDeactivations: pending}
	if err := savePersistedState(m.config.StateDir, candidate); err != nil {
		return err
	}
	m.stateMu.Lock()
	m.state = candidate
	m.stateMu.Unlock()
	m.publish(m.communitySnapshot())
	return m.releasePendingActivations(ctx)
}

// pendingActivationReleases owns its slice and never schedules the active seat.
func pendingActivationReleases(state persistedState, activationIDs ...string) []string {
	var pending []string
	seen := make(map[string]bool)
	for _, id := range append(append([]string(nil), state.PendingDeactivations...), activationIDs...) {
		if id != "" && id != state.ActivationID && !seen[id] {
			pending = append(pending, id)
			seen[id] = true
		}
	}
	return pending
}

// All callers hold operationMu. Persist changes before publishing them in memory.
func (m *RuntimeManager) queueActivationRelease(activationID string) error {
	m.stateMu.Lock()
	candidate := m.state
	m.stateMu.Unlock()
	candidate.PendingDeactivations = pendingActivationReleases(candidate, activationID)
	if err := savePersistedState(m.config.StateDir, candidate); err != nil {
		return err
	}
	m.stateMu.Lock()
	m.state = candidate
	m.stateMu.Unlock()
	return nil
}

func (m *RuntimeManager) releaseActivation(ctx context.Context, activationID string) error {
	nonce, err := randomNonce()
	if err != nil {
		return err
	}
	return m.client.deactivate(ctx, activationID, leaseRequest{
		ActivationID: activationID, InstallationID: m.identity.InstallationID,
		RuntimeID: m.identity.RuntimeID, Version: m.config.Version,
		Timestamp: m.config.Clock().UTC().Unix(), Nonce: nonce,
	}, m.identity.PrivateKey)
}

func (m *RuntimeManager) releasePendingActivations(ctx context.Context) error {
	if m.client == nil {
		return nil
	}
	m.stateMu.Lock()
	pending := pendingActivationReleases(m.state)
	m.stateMu.Unlock()
	var failures []error
	for _, id := range pending {
		if err := m.releaseActivation(ctx, id); err != nil {
			failures = append(failures, fmt.Errorf("release activation %s: %w", id, err))
			continue
		}
		m.stateMu.Lock()
		candidate := m.state
		remainingIDs := pendingActivationReleases(candidate)
		m.stateMu.Unlock()
		candidate.PendingDeactivations = nil
		for _, remaining := range remainingIDs {
			if remaining != id {
				candidate.PendingDeactivations = append(candidate.PendingDeactivations, remaining)
			}
		}
		if err := savePersistedState(m.config.StateDir, candidate); err != nil {
			// Keep the ID on disk on failure; DELETE is idempotent on retry.
			return errors.Join(append(failures, fmt.Errorf("persist activation release: %w", err))...)
		}
		m.stateMu.Lock()
		m.state = candidate
		m.stateMu.Unlock()
	}
	return errors.Join(failures...)
}

func (m *RuntimeManager) Start(ctx context.Context) {
	// Subscribers must see deadline transitions even when the authority is offline.
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.operationMu.Lock()
				previous := m.current.Load().(Snapshot)
				next := m.Snapshot()
				if previous.Status != next.Status || previous.EffectiveTier != next.EffectiveTier {
					m.publish(next)
				}
				m.operationMu.Unlock()
			}
		}
	}()
	if m.client == nil {
		return
	}
	go func() {
		// Reconcile immediately after startup. A persisted entitlement remains
		// usable offline, but release metadata must not wait hours to recover.
		refreshCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		_ = m.Refresh(refreshCtx)
		cancel()
		for {
			jitter := time.Duration(rand.Int63n(max(1, int64(m.config.RefreshInterval/5))))
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
	if !now.Before(claims.OfflineUntil.Time) {
		status = StatusExpired
		paidAllowed = false
	} else if now.After(claims.ExpiresAt.Time) && paidAllowed {
		status = StatusGrace
	}
	if !paidAllowed {
		upgrade = UpgradeInfo{}
	} else if upgrade.TargetTier != "" && upgrade.TargetTier != claims.Tier {
		// A response's unsigned release metadata cannot override the paid plan.
		upgrade = UpgradeInfo{TargetTier: claims.Tier, State: "unavailable", Reason: "The release edition does not match this licence. Refresh after a matching release is published."}
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
			if !upgrade.Available && upgrade.Reason == "" {
				upgrade.State = "unavailable"
				upgrade.Reason = "No compatible release is available for this installation. Refresh after the release is published."
			}
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
		clock:         m.config.Clock,
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
		m.stateMu.Lock()
		snapshot.ActivationID = m.state.ActivationID
		m.stateMu.Unlock()
		snapshot.Status = StatusInvalid
		snapshot.LastError = err.Error()
		m.publish(snapshot)
		return
	}
	if err := m.recordObservedTime(m.config.Clock().UTC()); err != nil {
		snapshot := m.communitySnapshot()
		m.stateMu.Lock()
		snapshot.ActivationID = m.state.ActivationID
		m.stateMu.Unlock()
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
		SignedKeySet:  m.config.SignedKeySet,
	}
	// Catalog availability is independent of whether a newer version is known.
	// An outage or compatibility failure must not be presented as up to date.
	switch response.ArtifactStatus {
	case "updater_upgrade_required":
		upgrade.State = "unavailable"
		minimum := strings.TrimSpace(response.ArtifactMinimumUpdaterVersion)
		if semver.IsValid(normalizeVersion(minimum)) {
			upgrade.MinimumUpdaterVersion = minimum
			upgrade.Reason = fmt.Sprintf("The local aegis-updater needs version %s or later before this release can be installed. Follow the standalone updater installation or native migration instructions, then refresh the licence.", minimum)
		} else {
			upgrade.Reason = "The local aegis-updater must be updated before this release can be installed. Follow the standalone updater installation or native migration instructions, then refresh the licence."
		}
	case "resolver_unavailable":
		upgrade.State, upgrade.Reason = "unavailable", "The commercial release catalog is unavailable. Retry the licence refresh after the licensing service recovers."
	case "unavailable":
		upgrade.State, upgrade.Reason = "unavailable", "No compatible commercial release is available for this installation. A release may be unpublished or require a newer aegis-updater. Check the updater version, then refresh after a compatible release is published."
	case "not_entitled":
		upgrade.State, upgrade.Reason = "unavailable", "This licence is not entitled to a commercial release. Refresh its status and verify the subscription."
	case "", "available":
		if response.ArtifactManifest == "" && (response.ArtifactStatus != "" || response.TargetTier != "") {
			upgrade.State, upgrade.Reason = "unavailable", "No signed commercial release manifest was returned. Check that a compatible release is published and the updater version is supported, then refresh the licence."
		} else if response.ArtifactStatus == "available" && (response.TargetTier == "" || !semver.IsValid(normalizeVersion(response.TargetVersion))) {
			upgrade.State, upgrade.Reason = "unavailable", "The commercial release catalog returned incomplete release metadata. Refresh after the licensing service recovers."
		}
	default:
		upgrade.State, upgrade.Reason = "unavailable", "The commercial release catalog returned an unsupported availability status. Refresh after the licensing service recovers."
	}
	if response.TargetTier == "" {
		return upgrade, nil
	}
	tier, err := edition.ParseBuildTier(response.TargetTier)
	if err != nil {
		// A bad release response must not reject an otherwise valid entitlement.
		return UpgradeInfo{State: "unavailable", Reason: "The release metadata has an invalid edition. Refresh after a matching release is published."}, nil
	}
	upgrade.TargetTier = tier

	// A paid plan change can also select a lower edition at the same release
	// version. This replaces the binary to match the signed entitlement while
	// the artifact checks below still reject a numeric version downgrade.
	isEditionChange := tier != m.config.CompiledTier && tier != edition.CommunityTier
	isVersionUpgrade := semver.IsValid(normalizeVersion(response.TargetVersion)) && semver.IsValid(normalizeVersion(m.config.Version)) &&
		semver.Compare(normalizeVersion(response.TargetVersion), normalizeVersion(m.config.Version)) > 0

	upgrade.Required = isEditionChange || (tier == m.config.CompiledTier && isVersionUpgrade)
	if upgrade.State == "unavailable" {
		upgrade.Manifest, upgrade.Credential = "", ""
		return upgrade, nil
	}
	if upgrade.Required {
		upgrade.State = "unavailable"
		upgrade.Reason = "No compatible release is available for this installation. Refresh after the release is published."
		if !semver.IsValid(normalizeVersion(m.config.Version)) {
			upgrade.Reason = "The running binary has no valid release version. Install an official versioned build before upgrading."
		} else if upgrade.Manifest != "" && semver.IsValid(normalizeVersion(upgrade.TargetVersion)) &&
			semver.Compare(normalizeVersion(upgrade.TargetVersion), normalizeVersion(m.config.Version)) >= 0 {
			validUntil, err := m.verifyUpgradeArtifact(upgrade)
			if err != nil {
				upgrade.Reason = "The release manifest could not be verified: " + err.Error()
			} else {
				upgrade.ValidUntil = validUntil
				upgrade.State, upgrade.Available, upgrade.Reason = "ready", true, ""
			}
		}
	}
	return upgrade, nil
}

func normalizeVersion(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, "v") {
		return value
	}
	return "v" + value
}
