//go:build linux || windows

package maintenance

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/divinelabio/aegis/internal/licensing"
	"github.com/google/uuid"
	"golang.org/x/mod/semver"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const maxReleaseArchive = 1 << 30

type UpdaterRequest struct {
	Operation    string `json:"operation"`
	Manifest     string `json:"manifest,omitempty"`
	Credential   string `json:"credential,omitempty"`
	SignedKeySet string `json:"signed_key_set,omitempty"`
}

type UpdaterResponse struct {
	UpdaterVersion string       `json:"updater_version,omitempty"`
	OK             bool         `json:"ok"`
	Error          string       `json:"error,omitempty"`
	Status         UpdaterState `json:"status"`
	Message        string       `json:"message,omitempty"`
}

type UpdaterState struct {
	JobID            string    `json:"job_id,omitempty"`
	CandidateTarget  string    `json:"candidate_target,omitempty"`
	CandidateEdition string    `json:"candidate_edition,omitempty"`
	CandidateVersion string    `json:"candidate_version,omitempty"`
	State            string    `json:"state"`
	Edition          string    `json:"edition,omitempty"`
	Version          string    `json:"version,omitempty"`
	PreviousEdition  string    `json:"previous_edition,omitempty"`
	PreviousVersion  string    `json:"previous_version,omitempty"`
	LastError        string    `json:"last_error,omitempty"`
	UpdatedAt        time.Time `json:"updated_at"`
	CurrentTarget    string    `json:"current_target,omitempty"`
	PreviousTarget   string    `json:"previous_target,omitempty"`
	KeySetVersion    int       `json:"key_set_version,omitempty"`
	KeySetHash       string    `json:"key_set_hash,omitempty"`
	SignedKeySet     string    `json:"signed_key_set,omitempty"`
}

type ReleaseDaemon struct {
	Config               UpdaterConfig
	Verifier             ManifestVerifier
	Version              string
	mu                   sync.Mutex
	stateMu              sync.Mutex
	running              bool
	stopping             bool
	jobCancel            context.CancelFunc
	jobs                 sync.WaitGroup
	restartOverride      func(context.Context) error
	nativeTargetOverride func() (string, error)
	nativeSwitchOverride func(string) error
	transport            http.RoundTripper
}

func (d *ReleaseDaemon) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	decoder := json.NewDecoder(io.LimitReader(conn, 2<<20))
	decoder.DisallowUnknownFields()
	var request UpdaterRequest
	if err := decoder.Decode(&request); err != nil {
		_ = json.NewEncoder(conn).Encode(UpdaterResponse{Error: "invalid updater request"})
		return
	}
	_ = json.NewEncoder(conn).Encode(d.Execute(ctx, request))
}
func (d *ReleaseDaemon) Execute(ctx context.Context, request UpdaterRequest) UpdaterResponse {
	if request.Operation == "status" {
		state, err := d.loadState()
		if err != nil {
			return UpdaterResponse{Error: err.Error()}
		}
		return UpdaterResponse{OK: true, Status: state, UpdaterVersion: d.Version}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.stopping {
		return UpdaterResponse{Error: "updater is stopping"}
	}
	if d.running {
		state, _ := d.loadState()
		return UpdaterResponse{Error: "an updater job is already running", Status: state}
	}
	var manifest ArtifactManifest
	if request.Operation == "upgrade" {
		previous, err := d.loadState()
		if err != nil {
			return UpdaterResponse{Error: err.Error()}
		}
		verifier := d.Verifier
		keySet := request.SignedKeySet
		if keySet == "" {
			keySet = previous.SignedKeySet
		}
		if keySet == "" {
			keySet = verifier.SignedKeySet
		}
		if keySet != "" {
			keys, err := licensing.CertifiedTrustedKeys(verifier.RootPublicKey, keySet, licensing.KeyPurposeArtifact, time.Now())
			if err != nil {
				return UpdaterResponse{Error: err.Error()}
			}
			version, err := licensing.CertifiedKeySetVersion(keySet)
			if err != nil {
				return UpdaterResponse{Error: err.Error()}
			}
			certificateHash := sha256.Sum256([]byte(keySet))
			fingerprint := hex.EncodeToString(certificateHash[:])
			if version < previous.KeySetVersion || (version == previous.KeySetVersion && previous.KeySetHash != "" && fingerprint != previous.KeySetHash) {
				return UpdaterResponse{Error: "artifact key set downgrade rejected"}
			}
			previous.KeySetVersion = version
			previous.KeySetHash = fingerprint
			previous.SignedKeySet = keySet
			verifier.Keys = keys
		} else if previous.KeySetVersion > 0 {
			return UpdaterResponse{Error: "certified artifact key set is required to preserve the persisted trust generation"}
		}
		manifest, err = verifier.Verify(strings.TrimSpace(request.Manifest))
		if err != nil {
			return UpdaterResponse{Error: err.Error()}
		}
		if manifest.MinimumUpdaterVersion != "" && compareVersions(d.Version, manifest.MinimumUpdaterVersion) < 0 {
			return UpdaterResponse{Error: "updater version is below the manifest minimum"}
		}
		if (d.Config.Mode == "native" && manifest.Format != "tar.gz" && manifest.Format != "zip") || (d.Config.Mode == "docker" && manifest.Format != "oci" && manifest.Format != "docker.tar.gz") {
			return UpdaterResponse{Error: "artifact format does not match configured updater mode"}
		}
		if keySet != "" {
			if err = d.saveState(previous); err != nil {
				return UpdaterResponse{Error: err.Error()}
			}
		}
	} else if request.Operation != "rollback" || request.Manifest != "" || request.Credential != "" || request.SignedKeySet != "" {
		return UpdaterResponse{Error: "unsupported updater operation or caller data"}
	}
	state, err := d.loadState()
	if err != nil {
		return UpdaterResponse{Error: err.Error()}
	}
	if state.State == "switching" || state.State == "checking" || state.State == "rolling_back" {
		return UpdaterResponse{Error: "interrupted release transition must be recovered before starting another job", Status: state}
	}
	if request.Operation == "upgrade" && d.Config.Mode == "native" {
		// A journal can outlive an installer/manual recovery. Compare against
		// the actual linked binary rather than rejecting based on stale state.
		if err = d.initializeBaseline(ctx, &state); err != nil {
			return UpdaterResponse{Error: err.Error(), Status: state}
		}
	}
	if request.Operation == "upgrade" && state.Version != "" && compareVersions(manifest.Version, state.Version) < 0 {
		return UpdaterResponse{Error: "artifact downgrade is not permitted"}
	}
	if request.Operation == "upgrade" && state.State == "active" && sameReleaseVersion(state.Version, manifest.Version) && state.Edition == string(manifest.Edition) {
		if d.waitHealthy(ctx, 2*time.Second, manifest.Version, string(manifest.Edition)) == nil {
			if err = d.saveState(state); err != nil {
				return UpdaterResponse{Error: err.Error()}
			}
			return UpdaterResponse{OK: true, Status: state, Message: "release already installed"}
		}
	}
	if request.Operation == "rollback" && state.PreviousTarget == "" {
		return UpdaterResponse{Error: "no previous release is available"}
	}
	state.JobID = uuid.NewString()
	state.State = "queued"
	state.LastError = ""
	state.UpdatedAt = time.Now().UTC()
	if err := d.saveState(state); err != nil {
		return UpdaterResponse{Error: err.Error()}
	}
	d.running = true
	jobCtx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	d.jobCancel = cancel
	d.jobs.Add(1)
	go func() {
		defer d.jobs.Done()
		defer func() { d.mu.Lock(); d.running = false; d.jobCancel = nil; d.mu.Unlock() }()
		// The job survives the HTTP caller and the Aegis restart. The daemon owns it.
		defer cancel()
		time.Sleep(250 * time.Millisecond)
		var jobErr error
		if request.Operation == "rollback" {
			jobErr = d.rollback(jobCtx)
		} else {
			jobErr = d.apply(jobCtx, manifest, request.Credential)
		}
		if jobErr != nil {
			_ = d.failure(jobErr)
		}
	}()
	return UpdaterResponse{OK: true, Status: state, Message: "updater job queued"}
}

// Retain the process lock until cancellation and any necessary rollback finish.
func (d *ReleaseDaemon) stopJobs() {
	d.mu.Lock()
	d.stopping = true
	if d.jobCancel != nil {
		d.jobCancel()
	}
	d.mu.Unlock()
	d.jobs.Wait()
}
func (d *ReleaseDaemon) apply(ctx context.Context, manifest ArtifactManifest, credential string) (applyErr error) {
	state, err := d.loadState()
	if err != nil {
		return err
	}
	if err = d.initializeBaseline(ctx, &state); err != nil {
		return err
	}
	if state.Version != "" && compareVersions(manifest.Version, state.Version) < 0 {
		return errors.New("artifact downgrade is not permitted")
	}
	state.PreviousTarget, state.PreviousEdition, state.PreviousVersion = state.CurrentTarget, state.Edition, state.Version
	state.State = "installing"
	state.UpdatedAt = time.Now().UTC()
	if err = d.saveState(state); err != nil {
		return err
	}
	var target string
	if d.Config.Mode == "native" {
		target, err = d.prepareNative(ctx, manifest, credential)
	} else {
		target, err = d.prepareDocker(ctx, manifest, credential)
	}
	if err != nil {
		return err
	}
	state.CandidateTarget = target
	state.CandidateEdition = string(manifest.Edition)
	state.CandidateVersion = manifest.Version
	state.State = "switching"
	state.UpdatedAt = time.Now().UTC()
	if err = d.saveState(state); err != nil {
		return err
	}
	switched := false
	defer func() {
		if applyErr != nil && switched {
			rollbackCtx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			if rollbackErr := d.rollback(rollbackCtx); rollbackErr != nil {
				applyErr = errors.Join(applyErr, fmt.Errorf("rollback failed: %w", rollbackErr))
			}
		}
	}()
	// A platform switch can report an error after changing the link (for
	// example, a directory sync failure). Conservatively restore the baseline.
	switched = true
	if err = d.switchTarget(ctx, target); err != nil {
		return err
	}
	state.CurrentTarget = target
	state.State = "checking"
	state.Edition = string(manifest.Edition)
	state.Version = manifest.Version
	if err = d.saveState(state); err != nil {
		return err
	}
	if err = d.restart(ctx); err != nil {
		return err
	}
	if err = d.waitHealthy(ctx, 60*time.Second, manifest.Version, string(manifest.Edition)); err != nil {
		return err
	}
	state.State = "active"
	state.LastError = ""
	state.CandidateTarget = ""
	state.CandidateEdition, state.CandidateVersion = "", ""
	state.UpdatedAt = time.Now().UTC()
	return d.saveState(state)
}
func (d *ReleaseDaemon) initializeBaseline(ctx context.Context, state *UpdaterState) error {
	if d.Config.Mode == "native" {
		actual, err := d.resolveNativeTarget()
		if err != nil {
			return fmt.Errorf("resolve current release: %w", err)
		}
		if !pathWithin(d.Config.ReleasesRoot, actual) {
			return errors.New("current release is outside the configured release root")
		}
		state.CurrentTarget = actual
		info, err := readBuildInfo(ctx, actual)
		if err != nil {
			return fmt.Errorf("inspect current release baseline: %w", err)
		}
		if !semver.IsValid(normalizeVersion(info.Version)) || (info.BuildTier != "community" && info.BuildTier != "professional" && info.BuildTier != "enterprise") {
			return errors.New("current release baseline has invalid build identity")
		}
		state.Version = info.Version
		state.Edition = info.BuildTier
	} else {
		if state.CurrentTarget == "" {
			data, err := os.ReadFile(d.Config.ReleaseEnvPath)
			if err != nil {
				return fmt.Errorf("read initial image: %w", err)
			}
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "AEGIS_IMAGE=") {
					state.CurrentTarget = strings.TrimPrefix(line, "AEGIS_IMAGE=")
				}
			}
		}
		if state.CurrentTarget == "" || !imagePattern.MatchString(state.CurrentTarget) {
			return errors.New("initial image reference is missing or invalid")
		}
		info, err := d.dockerBuildInfo(ctx, state.CurrentTarget)
		if err != nil || !semver.IsValid(normalizeVersion(info.Version)) || (info.BuildTier != "community" && info.BuildTier != "professional" && info.BuildTier != "enterprise") {
			return errors.New("initial Docker image has invalid build identity")
		}
		state.Edition, state.Version = info.BuildTier, info.Version
	}
	return nil
}

type releaseBuildInfo struct {
	Version   string `json:"version"`
	BuildTier string `json:"build_tier"`
}

func binaryName(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}
func readBuildInfo(ctx context.Context, root string) (releaseBuildInfo, error) {
	var info releaseBuildInfo
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(probeCtx, filepath.Join(root, binaryName("aegis")), "--build-info").Output()
	if err != nil {
		return info, err
	}
	err = json.Unmarshal(output, &info)
	return info, err
}
func (d *ReleaseDaemon) prepareNative(ctx context.Context, manifest ArtifactManifest, credential string) (string, error) {
	archive, err := d.download(ctx, manifest, credential)
	if err != nil {
		return "", err
	}
	defer os.Remove(archive)
	staging, err := os.MkdirTemp(d.Config.ReleasesRoot, ".aegis-release-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(staging)
	if err = extractRelease(archive, staging); err != nil {
		return "", err
	}
	if err = secureRelease(staging); err != nil {
		return "", err
	}
	info, err := readBuildInfo(ctx, staging)
	if err != nil {
		return "", fmt.Errorf("inspect release binary: %w", err)
	}
	if !sameReleaseVersion(info.Version, manifest.Version) || info.BuildTier != string(manifest.Edition) {
		return "", errors.New("release binary version or edition differs from its signed manifest")
	}
	// A unique target keeps an active release intact even when reinstalling the same version.
	target := filepath.Join(d.Config.ReleasesRoot, manifest.Version+"-"+string(manifest.Edition)+"-"+uuid.NewString())
	if err = os.Rename(staging, target); err != nil {
		return "", err
	}
	if err = syncReleaseDirectory(d.Config.ReleasesRoot); err != nil {
		return "", err
	}
	return target, nil
}
func (d *ReleaseDaemon) prepareDocker(ctx context.Context, manifest ArtifactManifest, credential string) (string, error) {
	if manifest.Format == "docker.tar.gz" {
		archive, err := d.download(ctx, manifest, credential)
		if err != nil {
			return "", err
		}
		defer os.Remove(archive)
		if err = fixedCommand(ctx, d.Config.ContainerRuntime, "load", "--input", archive); err != nil {
			return "", errors.New("load signed Docker archive failed")
		}
		output, err := commandOutput(ctx, d.Config.ContainerRuntime, "image", "inspect", manifest.Image, "--format", "{{.Id}}")
		if err != nil || strings.TrimSpace(output) != manifest.Image {
			return "", errors.New("loaded Docker image differs from the signed image identity")
		}
		info, err := d.dockerBuildInfo(ctx, manifest.Image)
		if err != nil || !sameReleaseVersion(info.Version, manifest.Version) || info.BuildTier != string(manifest.Edition) {
			return "", errors.New("Docker binary version or edition differs from its signed manifest")
		}
		return manifest.Image, nil
	}
	if credential != "" {
		registry := strings.SplitN(manifest.Image, "/", 2)[0]
		login := exec.CommandContext(ctx, d.Config.ContainerRuntime, "login", registry, "--username", "aegis-token", "--password-stdin")
		login.Stdin = strings.NewReader(credential)
		if err := login.Run(); err != nil {
			return "", errors.New("registry login failed")
		}
		defer fixedCommand(context.Background(), d.Config.ContainerRuntime, "logout", registry)
	}
	if err := fixedCommand(ctx, d.Config.ContainerRuntime, "pull", manifest.Image); err != nil {
		return "", err
	}
	info, err := d.dockerBuildInfo(ctx, manifest.Image)
	if err != nil || !sameReleaseVersion(info.Version, manifest.Version) || info.BuildTier != string(manifest.Edition) {
		return "", errors.New("Docker binary version or edition differs from its signed manifest")
	}
	return manifest.Image, nil
}
func (d *ReleaseDaemon) dockerBuildInfo(ctx context.Context, image string) (releaseBuildInfo, error) {
	var info releaseBuildInfo
	output, err := commandOutput(ctx, d.Config.ContainerRuntime, "run", "--rm", "--network", "none", "--entrypoint", "/aegis", image, "--build-info")
	if err == nil {
		err = json.Unmarshal([]byte(output), &info)
	}
	return info, err
}
func (d *ReleaseDaemon) switchTarget(ctx context.Context, target string) error {
	if d.Config.Mode == "native" {
		if d.nativeSwitchOverride != nil {
			return d.nativeSwitchOverride(target)
		}
		return atomicSymlink(target, d.Config.CurrentLink)
	}
	return d.writeReleaseImage(target)
}

func (d *ReleaseDaemon) resolveNativeTarget() (string, error) {
	if d.nativeTargetOverride != nil {
		return d.nativeTargetOverride()
	}
	return filepath.EvalSymlinks(d.Config.CurrentLink)
}

func (d *ReleaseDaemon) writeReleaseImage(target string) error {
	if !imagePattern.MatchString(target) {
		return errors.New("invalid image reference")
	}
	data, err := os.ReadFile(d.Config.ReleaseEnvPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	updated := false
	for index, line := range lines {
		if strings.HasPrefix(line, "AEGIS_IMAGE=") {
			lines[index] = "AEGIS_IMAGE=" + target
			updated = true
		}
	}
	if !updated {
		lines = append(lines, "AEGIS_IMAGE="+target)
	}
	return writeAtomicFile(d.Config.ReleaseEnvPath, []byte(strings.Join(lines, "\n")+"\n"), 0600)
}
func (d *ReleaseDaemon) restart(ctx context.Context) error {
	if d.restartOverride != nil {
		return d.restartOverride(ctx)
	}
	if d.Config.Mode == "native" {
		return restartService(ctx, d.Config.ServiceName)
	}
	command := exec.CommandContext(ctx, d.Config.ContainerRuntime, "compose", "--env-file", d.Config.ReleaseEnvPath, "-f", d.Config.ComposePath, "up", "-d", "--no-deps", d.Config.ComposeService)
	// A host shell variable must not override the manifest's pinned image.
	for _, variable := range os.Environ() {
		if !strings.HasPrefix(variable, "AEGIS_IMAGE=") {
			command.Env = append(command.Env, variable)
		}
	}
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("compose restart failed: %s", strings.TrimSpace(string(output)))
	}
	return nil
}
func (d *ReleaseDaemon) rollback(ctx context.Context) error {
	state, err := d.loadState()
	if err != nil {
		return err
	}
	if state.PreviousTarget == "" {
		return errors.New("no previous release is available")
	}
	if d.Config.Mode == "native" && !pathWithin(d.Config.ReleasesRoot, state.PreviousTarget) {
		return errors.New("previous target is outside the release root")
	}
	// Record rollback intent before changing the link. Recovery can complete it
	// whether the process stops immediately before or after the switch.
	if state.CandidateTarget != "" && state.CurrentTarget == state.PreviousTarget {
		state.CurrentTarget = state.CandidateTarget
		state.Edition, state.Version = state.CandidateEdition, state.CandidateVersion
	}
	state.CurrentTarget, state.PreviousTarget = state.PreviousTarget, state.CurrentTarget
	state.Edition, state.PreviousEdition = state.PreviousEdition, state.Edition
	state.Version, state.PreviousVersion = state.PreviousVersion, state.Version
	state.State = "rolling_back"
	state.CandidateTarget = ""
	state.CandidateEdition, state.CandidateVersion = "", ""
	state.UpdatedAt = time.Now().UTC()
	if err = d.saveState(state); err != nil {
		return err
	}
	if err = d.switchTarget(ctx, state.CurrentTarget); err != nil {
		return err
	}
	if err = d.restart(ctx); err != nil {
		return err
	}
	if err = d.waitHealthyRelease(ctx, 60*time.Second, state.Version, state.Edition, false); err != nil {
		return err
	}
	state.State = "rolled_back"
	state.UpdatedAt = time.Now().UTC()
	return d.saveState(state)
}
func (d *ReleaseDaemon) recoverInterrupted(ctx context.Context) error {
	state, err := d.loadState()
	if err != nil {
		return err
	}
	switch state.State {
	case "switching", "checking":
		if state.PreviousTarget == "" {
			return errors.New("interrupted upgrade has no recorded rollback target")
		}
		if err = d.rollback(ctx); err != nil {
			return err
		}
	case "rolling_back":
		// The rollback journal already names the restored release as current.
		// Complete that switch rather than swapping back to the failed release.
		if err = d.switchTarget(ctx, state.CurrentTarget); err != nil {
			return err
		}
		if err = d.restart(ctx); err != nil {
			return err
		}
		if err = d.waitHealthyRelease(ctx, 60*time.Second, state.Version, state.Edition, false); err != nil {
			return err
		}
		state.State = "rolled_back"
		state.UpdatedAt = time.Now().UTC()
		if err = d.saveState(state); err != nil {
			return err
		}
	case "queued", "installing":
	default:
		return nil
	}
	_ = d.failure(errors.New("updater stopped during its previous job; previous release preserved"))
	return nil
}
func (d *ReleaseDaemon) waitHealthy(ctx context.Context, limit time.Duration, version, tier string) error {
	return d.waitHealthyRelease(ctx, limit, version, tier, true)
}
func (d *ReleaseDaemon) waitHealthyRelease(ctx context.Context, limit time.Duration, version, tier string, requireLicensed bool) error {
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, d.Config.HealthURL, nil)
		if err != nil {
			return err
		}
		response, err := client.Do(request)
		if err == nil {
			var health struct {
				Status        string `json:"status"`
				Version       string `json:"version"`
				BuildTier     string `json:"build_tier"`
				EffectiveTier string `json:"effective_tier"`
			}
			decodeErr := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&health)
			response.Body.Close()
			if response.StatusCode == 200 && decodeErr == nil && (health.Status == "healthy" || health.Status == "degraded") && (version == "" || sameReleaseVersion(health.Version, version)) && (tier == "" || (health.BuildTier == tier && (!requireLicensed || health.EffectiveTier == tier))) {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return errors.New("release did not become healthy with the expected version and licensed edition")
}
func validateReleaseFiles(root string) error {
	for _, name := range []string{"aegis", "aegisctl", "aegis-updater"} {
		info, err := os.Stat(filepath.Join(root, binaryName(name)))
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			return fmt.Errorf("release is missing a nonempty %s binary", name)
		}
	}
	return nil
}
func extractZipRelease(archive, destination string) error {
	reader, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer reader.Close()
	var total uint64
	if len(reader.File) > 512 {
		return errors.New("release archive has too many files")
	}
	for _, file := range reader.File {
		total += file.UncompressedSize64
		if total > maxReleaseArchive {
			return errors.New("release archive exceeds extraction limits")
		}
		name := filepath.Clean(file.Name)
		target := filepath.Join(destination, name)
		if !pathWithin(destination, target) || file.Mode()&os.ModeSymlink != 0 {
			return errors.New("release archive contains traversal or links")
		}
		if file.FileInfo().IsDir() {
			if err = os.MkdirAll(target, 0755); err != nil {
				return err
			}
			continue
		}
		if !file.Mode().IsRegular() {
			return errors.New("release archive contains a special file")
		}
		if err = os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		input, err := file.Open()
		if err != nil {
			return err
		}
		output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0755)
		if err != nil {
			input.Close()
			return err
		}
		written, copyErr := io.Copy(output, io.LimitReader(input, maxReleaseArchive+1))
		if copyErr == nil && uint64(written) != file.UncompressedSize64 {
			copyErr = errors.New("release file size differs from archive header")
		}
		if copyErr == nil {
			copyErr = output.Sync()
		}
		input.Close()
		closeErr := output.Close()
		if copyErr != nil || closeErr != nil {
			return errors.New("could not extract release file")
		}
	}
	return validateReleaseFiles(destination)
}
func commandOutput(ctx context.Context, name string, args ...string) (string, error) {
	output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s failed: %s", name, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}
func CallUpdater(ctx context.Context, socket string, request UpdaterRequest) (UpdaterResponse, error) {
	conn, err := dialUpdater(ctx, socket)
	if err != nil {
		return UpdaterResponse{}, err
	}
	defer conn.Close()
	deadline := time.Now().Add(20 * time.Second)
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) {
		deadline = value
	}
	_ = conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if err = json.NewEncoder(conn).Encode(request); err != nil {
		return UpdaterResponse{}, err
	}
	var response UpdaterResponse
	if err = json.NewDecoder(io.LimitReader(conn, 2<<20)).Decode(&response); err != nil {
		return response, err
	}
	if !response.OK {
		return response, errors.New(response.Error)
	}
	return response, nil
}
func (d *ReleaseDaemon) download(ctx context.Context, manifest ArtifactManifest, credential string) (string, error) {
	parsed, _ := url.Parse(manifest.URL)
	client := &http.Client{Timeout: 10 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 2 || req.URL.Scheme != "https" || !strings.EqualFold(req.URL.Host, parsed.Host) {
			return errors.New("artifact redirect left its signed HTTPS origin")
		}
		return nil
	}}
	if d.transport != nil {
		client.Transport = d.transport
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, manifest.URL, nil)
	if err != nil {
		return "", err
	}
	if credential != "" {
		request.Header.Set("Authorization", "Bearer "+credential)
	}
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ContentLength > maxReleaseArchive {
		return "", fmt.Errorf("artifact download returned HTTP %d or exceeded the size limit", response.StatusCode)
	}
	if err := os.MkdirAll(d.Config.ReleasesRoot, 0o755); err != nil {
		return "", err
	}
	suffix := ".tar.gz"
	if manifest.Format == "zip" {
		suffix = ".zip"
	}
	file, err := os.CreateTemp(d.Config.ReleasesRoot, ".aegis-download-*"+suffix)
	if err != nil {
		return "", err
	}
	path := file.Name()
	defer func() {
		if err != nil {
			os.Remove(path)
		}
	}()
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(response.Body, maxReleaseArchive+1))
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil || written > maxReleaseArchive {
		os.Remove(path)
		return "", errors.New("artifact download failed or exceeded the size limit")
	}
	actual := "sha256:" + hex.EncodeToString(hash.Sum(nil))
	if actual != manifest.Digest {
		os.Remove(path)
		return "", errors.New("artifact digest does not match signed manifest")
	}
	return path, nil
}

func extractRelease(archive, destination string) error {
	if strings.HasSuffix(archive, ".zip") {
		return extractZipRelease(archive, destination)
	}
	var total int64
	files := 0
	file, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gz.Close()
	reader := tar.NewReader(gz)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return validateReleaseFiles(destination)
		}
		if err != nil {
			return err
		}
		files++
		total += header.Size
		if files > 512 || header.Size < 0 || total > maxReleaseArchive {
			return errors.New("release archive exceeds extraction limits")
		}
		name := filepath.Clean(header.Name)
		if filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
			return errors.New("release archive contains path traversal")
		}
		target := filepath.Join(destination, name)
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			mode := os.FileMode(header.Mode) & 0o755
			out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
			if err != nil {
				return err
			}
			written, copyErr := io.Copy(out, io.LimitReader(reader, header.Size))
			if copyErr == nil && written != header.Size {
				copyErr = errors.New("release file size differs from archive header")
			}
			if copyErr == nil {
				copyErr = out.Sync()
			}
			closeErr := out.Close()
			if copyErr != nil || closeErr != nil {
				return errors.New("could not extract release file")
			}
		default:
			return errors.New("release archive contains links or special files")
		}
	}
}

func (d *ReleaseDaemon) loadState() (UpdaterState, error) {
	d.stateMu.Lock()
	defer d.stateMu.Unlock()
	data, err := os.ReadFile(d.Config.StatePath)
	if os.IsNotExist(err) {
		return UpdaterState{State: "idle"}, nil
	}
	if err != nil {
		return UpdaterState{}, err
	}
	var state UpdaterState
	if err := json.Unmarshal(data, &state); err != nil {
		return UpdaterState{}, err
	}
	return state, nil
}

func (d *ReleaseDaemon) saveState(state UpdaterState) error {
	d.stateMu.Lock()
	defer d.stateMu.Unlock()
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomicFile(d.Config.StatePath, data, 0o600)
}

func (d *ReleaseDaemon) failure(err error) UpdaterResponse {
	state, loadErr := d.loadState()
	if loadErr != nil {
		err = errors.Join(err, fmt.Errorf("read updater failure journal: %w", loadErr))
		log.Printf("updater failure could not be journaled: %v", err)
		return UpdaterResponse{Error: err.Error()}
	}
	// Preserve outstanding side-effect intent so restart can recover it.
	if state.State != "switching" && state.State != "checking" && state.State != "rolling_back" {
		state.State = "failed"
	}
	state.LastError, state.UpdatedAt = err.Error(), time.Now().UTC()
	if saveErr := d.saveState(state); saveErr != nil {
		err = errors.Join(err, fmt.Errorf("persist updater failure: %w", saveErr))
	}
	log.Printf("updater job %s failed: %v", state.JobID, err)
	return UpdaterResponse{Error: err.Error(), Status: state}
}

func validateUpdaterConfig(config UpdaterConfig) error {
	if !filepath.IsAbs(config.StatePath) || (config.Mode == "native" && (!filepath.IsAbs(config.ReleasesRoot) || !filepath.IsAbs(config.CurrentLink))) {
		return errors.New("updater release and state paths must be absolute")
	}
	if config.SocketPath == "" || config.StatePath == "" || config.Mode != "native" && config.Mode != "docker" {
		return errors.New("updater paths and mode are invalid")
	}
	if config.Mode == "docker" && (config.ComposePath == "" || !filepath.IsAbs(config.ComposePath) || config.ComposeService == "" || !filepath.IsAbs(config.ReleaseEnvPath)) {
		return errors.New("Docker updater requires a fixed absolute Compose path and service")
	}
	return nil
}

func writeAtomicFile(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".aegis-updater-")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err = temporary.Chmod(mode); err == nil {
		_, err = temporary.Write(data)
	}
	if err == nil {
		err = temporary.Sync()
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = replaceFile(name, path); err != nil {
		return err
	}
	return syncReleaseDirectory(filepath.Dir(path))
}

func fixedCommand(ctx context.Context, name string, args ...string) error {
	command := exec.CommandContext(ctx, name, args...)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s failed: %s", name, strings.TrimSpace(string(output)))
	}
	return nil
}

func pathWithin(root, target string) bool {
	relative, err := filepath.Rel(root, target)
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func compareVersions(left, right string) int {
	return semver.Compare(normalizeVersion(left), normalizeVersion(right))
}

func sameReleaseVersion(left, right string) bool {
	return semver.IsValid(normalizeVersion(left)) && semver.IsValid(normalizeVersion(right)) && normalizeVersion(left) == normalizeVersion(right)
}
