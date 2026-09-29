//go:build linux

package maintenance

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/mod/semver"
)

const maxReleaseArchive = 1 << 30

type UpdaterRequest struct {
	Operation  string `json:"operation"`
	Manifest   string `json:"manifest,omitempty"`
	Credential string `json:"credential,omitempty"`
}

type UpdaterResponse struct {
	OK      bool         `json:"ok"`
	Error   string       `json:"error,omitempty"`
	Status  UpdaterState `json:"status"`
	Message string       `json:"message,omitempty"`
}

type UpdaterState struct {
	State           string    `json:"state"`
	Edition         string    `json:"edition,omitempty"`
	Version         string    `json:"version,omitempty"`
	PreviousEdition string    `json:"previous_edition,omitempty"`
	PreviousVersion string    `json:"previous_version,omitempty"`
	LastError       string    `json:"last_error,omitempty"`
	UpdatedAt       time.Time `json:"updated_at"`
	CurrentTarget   string    `json:"current_target,omitempty"`
	PreviousTarget  string    `json:"previous_target,omitempty"`
}

type ReleaseDaemon struct {
	Config   UpdaterConfig
	Verifier ManifestVerifier
	Version  string
	mu       sync.Mutex
}

func (d *ReleaseDaemon) Serve(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return errors.New("aegis-updater serve must run as root")
	}
	if err := validateUpdaterConfig(d.Config); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(d.Config.SocketPath), 0o750); err != nil {
		return err
	}
	if err := os.Remove(d.Config.SocketPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	listener, err := net.Listen("unix", d.Config.SocketPath)
	if err != nil {
		return err
	}
	defer listener.Close()
	defer os.Remove(d.Config.SocketPath)
	if group, err := user.LookupGroup("aegis"); err == nil {
		gid, _ := strconv.Atoi(group.Gid)
		_ = os.Chown(d.Config.SocketPath, 0, gid)
	}
	if err := os.Chmod(d.Config.SocketPath, 0o660); err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go d.handleConnection(ctx, conn)
	}
}

func (d *ReleaseDaemon) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))
	decoder := json.NewDecoder(io.LimitReader(conn, 2<<20))
	decoder.DisallowUnknownFields()
	var request UpdaterRequest
	if err := decoder.Decode(&request); err != nil {
		_ = json.NewEncoder(conn).Encode(UpdaterResponse{Error: "invalid updater request"})
		return
	}
	response := d.Execute(ctx, request)
	_ = json.NewEncoder(conn).Encode(response)
}

func (d *ReleaseDaemon) Execute(ctx context.Context, request UpdaterRequest) UpdaterResponse {
	d.mu.Lock()
	defer d.mu.Unlock()
	switch request.Operation {
	case "status":
		state, err := d.loadState()
		if err != nil {
			return UpdaterResponse{Error: err.Error()}
		}
		return UpdaterResponse{OK: true, Status: state}
	case "upgrade":
		manifest, err := d.Verifier.Verify(request.Manifest)
		if err != nil {
			return d.failure(err)
		}
		if manifest.MinimumUpdaterVersion != "" && compareVersions(d.Version, manifest.MinimumUpdaterVersion) < 0 {
			return d.failure(errors.New("updater version is below the manifest minimum"))
		}
		if err := d.apply(ctx, manifest, request.Credential); err != nil {
			_ = d.rollback(ctx)
			return d.failure(err)
		}
		state, _ := d.loadState()
		return UpdaterResponse{OK: true, Status: state, Message: "upgrade applied"}
	case "rollback":
		if request.Manifest != "" || request.Credential != "" {
			return d.failure(errors.New("rollback does not accept caller data"))
		}
		if err := d.rollback(ctx); err != nil {
			return d.failure(err)
		}
		state, _ := d.loadState()
		return UpdaterResponse{OK: true, Status: state, Message: "rollback applied"}
	default:
		return d.failure(errors.New("unsupported updater operation"))
	}
}

func (d *ReleaseDaemon) apply(ctx context.Context, manifest ArtifactManifest, credential string) error {
	state, _ := d.loadState()
	if state.Version != "" && compareVersions(manifest.Version, state.Version) < 0 {
		return errors.New("artifact downgrade is not permitted")
	}
	state.PreviousEdition, state.PreviousVersion = state.Edition, state.Version
	state.PreviousTarget = state.CurrentTarget
	state.State = "installing"
	state.UpdatedAt = time.Now().UTC()
	_ = d.saveState(state)
	var target string
	var err error
	if manifest.Format == "tar.gz" && d.Config.Mode == "native" {
		target, err = d.applyNative(ctx, manifest, credential)
	} else if manifest.Format == "oci" && d.Config.Mode == "docker" {
		target, err = d.applyDocker(ctx, manifest, credential)
	} else {
		err = errors.New("artifact format does not match configured updater mode")
	}
	if err != nil {
		return err
	}
	if err := d.waitHealthy(ctx, 60*time.Second); err != nil {
		return err
	}
	state.State = "active"
	state.Edition, state.Version = string(manifest.Edition), manifest.Version
	state.CurrentTarget, state.LastError = target, ""
	state.UpdatedAt = time.Now().UTC()
	return d.saveState(state)
}

func (d *ReleaseDaemon) applyNative(ctx context.Context, manifest ArtifactManifest, credential string) (string, error) {
	archive, err := d.download(ctx, manifest, credential)
	if err != nil {
		return "", err
	}
	defer os.Remove(archive)
	target := filepath.Join(d.Config.ReleasesRoot, manifest.Version+"-"+string(manifest.Edition))
	staging, err := os.MkdirTemp(d.Config.ReleasesRoot, ".aegis-release-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(staging)
	if err := extractRelease(archive, staging); err != nil {
		return "", err
	}
	if err := os.Rename(staging, target); err != nil {
		return "", err
	}
	if err := atomicSymlink(target, d.Config.CurrentLink); err != nil {
		return "", err
	}
	if err := fixedCommand(ctx, "systemctl", "restart", d.Config.ServiceName); err != nil {
		return "", err
	}
	return target, nil
}

func (d *ReleaseDaemon) applyDocker(ctx context.Context, manifest ArtifactManifest, credential string) (string, error) {
	if credential == "" {
		return "", errors.New("short-lived registry credential is required")
	}
	registry := strings.SplitN(manifest.Image, "/", 2)[0]
	login := exec.CommandContext(ctx, d.Config.ContainerRuntime, "login", registry, "--username", "aegis-token", "--password-stdin")
	login.Stdin = strings.NewReader(credential)
	if output, err := login.CombinedOutput(); err != nil {
		return "", fmt.Errorf("registry login failed: %s", strings.TrimSpace(string(output)))
	}
	defer fixedCommand(context.Background(), d.Config.ContainerRuntime, "logout", registry)
	if err := fixedCommand(ctx, d.Config.ContainerRuntime, "pull", manifest.Image); err != nil {
		return "", err
	}
	previous, _ := os.ReadFile(d.Config.ReleaseEnvPath)
	if err := writeAtomicFile(d.Config.ReleaseEnvPath, []byte("AEGIS_IMAGE="+manifest.Image+"\n"), 0o600); err != nil {
		return "", err
	}
	if err := fixedCommand(ctx, d.Config.ContainerRuntime, "compose", "-f", d.Config.ComposePath, "up", "-d", "--no-deps", d.Config.ComposeService); err != nil {
		_ = writeAtomicFile(d.Config.ReleaseEnvPath, previous, 0o600)
		return "", err
	}
	return manifest.Image, nil
}

func (d *ReleaseDaemon) download(ctx context.Context, manifest ArtifactManifest, credential string) (string, error) {
	parsed, _ := url.Parse(manifest.URL)
	client := &http.Client{Timeout: 10 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 2 || req.URL.Scheme != "https" || !strings.EqualFold(req.URL.Host, parsed.Host) {
			return errors.New("artifact redirect left its signed HTTPS origin")
		}
		return nil
	}}
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
	file, err := os.CreateTemp(d.Config.ReleasesRoot, ".aegis-download-")
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
			return nil
		}
		if err != nil {
			return err
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
			_, copyErr := io.Copy(out, io.LimitReader(reader, header.Size))
			closeErr := out.Close()
			if copyErr != nil || closeErr != nil {
				return errors.New("could not extract release file")
			}
		default:
			return errors.New("release archive contains links or special files")
		}
	}
}

func (d *ReleaseDaemon) rollback(ctx context.Context) error {
	state, err := d.loadState()
	if err != nil || state.PreviousTarget == "" {
		return errors.New("no previous release is available")
	}
	if d.Config.Mode == "native" {
		if !pathWithin(d.Config.ReleasesRoot, state.PreviousTarget) {
			return errors.New("previous release target is outside the release root")
		}
		if err := atomicSymlink(state.PreviousTarget, d.Config.CurrentLink); err != nil {
			return err
		}
		if err := fixedCommand(ctx, "systemctl", "restart", d.Config.ServiceName); err != nil {
			return err
		}
	} else {
		if !imagePattern.MatchString(state.PreviousTarget) {
			return errors.New("previous image reference is invalid")
		}
		if err := writeAtomicFile(d.Config.ReleaseEnvPath, []byte("AEGIS_IMAGE="+state.PreviousTarget+"\n"), 0o600); err != nil {
			return err
		}
		if err := fixedCommand(ctx, d.Config.ContainerRuntime, "compose", "-f", d.Config.ComposePath, "up", "-d", "--no-deps", d.Config.ComposeService); err != nil {
			return err
		}
	}
	state.State = "rolled_back"
	state.Edition, state.PreviousEdition = state.PreviousEdition, state.Edition
	state.Version, state.PreviousVersion = state.PreviousVersion, state.Version
	state.CurrentTarget, state.PreviousTarget = state.PreviousTarget, state.CurrentTarget
	state.UpdatedAt = time.Now().UTC()
	return d.saveState(state)
}

func (d *ReleaseDaemon) waitHealthy(ctx context.Context, limit time.Duration) error {
	deadline := time.Now().Add(limit)
	client := &http.Client{Timeout: 2 * time.Second}
	for time.Now().Before(deadline) {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, d.Config.HealthURL, nil)
		response, err := client.Do(request)
		if err == nil {
			response.Body.Close()
			if response.StatusCode >= 200 && response.StatusCode < 300 {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return errors.New("new release did not become healthy within 60 seconds")
}

func (d *ReleaseDaemon) loadState() (UpdaterState, error) {
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
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomicFile(d.Config.StatePath, data, 0o600)
}

func (d *ReleaseDaemon) failure(err error) UpdaterResponse {
	state, _ := d.loadState()
	state.State, state.LastError, state.UpdatedAt = "failed", err.Error(), time.Now().UTC()
	_ = d.saveState(state)
	return UpdaterResponse{Error: err.Error(), Status: state}
}

func validateUpdaterConfig(config UpdaterConfig) error {
	if config.SocketPath == "" || config.StatePath == "" || config.Mode != "native" && config.Mode != "docker" {
		return errors.New("updater paths and mode are invalid")
	}
	if config.Mode == "docker" && (config.ComposePath == "" || !filepath.IsAbs(config.ComposePath) || config.ComposeService == "") {
		return errors.New("Docker updater requires a fixed absolute Compose path and service")
	}
	return nil
}

func atomicSymlink(target, link string) error {
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		return err
	}
	temporary := link + ".new"
	_ = os.Remove(temporary)
	if err := os.Symlink(target, temporary); err != nil {
		return err
	}
	return os.Rename(temporary, link)
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
	if err := temporary.Chmod(mode); err == nil {
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
	return os.Rename(name, path)
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
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func compareVersions(left, right string) int {
	return semver.Compare(normalizeVersion(left), normalizeVersion(right))
}

func CallUpdater(ctx context.Context, socket string, request UpdaterRequest) (UpdaterResponse, error) {
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "unix", socket)
	if err != nil {
		return UpdaterResponse{}, err
	}
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return UpdaterResponse{}, err
	}
	var response UpdaterResponse
	if err := json.NewDecoder(io.LimitReader(conn, 2<<20)).Decode(&response); err != nil {
		return UpdaterResponse{}, err
	}
	if !response.OK {
		return response, errors.New(response.Error)
	}
	return response, nil
}
