//go:build linux || windows

package maintenance

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testArchive(t *testing.T, headers []*tar.Header) string {
	t.Helper()
	archive := filepath.Join(t.TempDir(), "release.tar.gz")
	file, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter := gzip.NewWriter(file)
	writer := tar.NewWriter(gzipWriter)
	for _, header := range headers {
		if err = writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Size > 0 && header.Size < 100 {
			if _, err = writer.Write(make([]byte, header.Size)); err != nil {
				t.Fatal(err)
			}
		}
	}
	_ = writer.Close()
	_ = gzipWriter.Close()
	_ = file.Close()
	return archive
}

func TestRejectUnsafeAndIncompleteReleases(t *testing.T) {
	for name, headers := range map[string][]*tar.Header{
		"empty": {}, "traversal": {{Name: "../aegis", Mode: 0755, Size: 1}}, "symlink": {{Name: "aegis", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}},
		"missing updater": {{Name: binaryName("aegis"), Mode: 0755, Size: 1}, {Name: binaryName("aegisctl"), Mode: 0755, Size: 1}},
		"oversized":       {{Name: "oversized", Mode: 0644, Size: maxReleaseArchive + 1}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := extractRelease(testArchive(t, headers), t.TempDir()); err == nil {
				t.Fatal("invalid release was accepted")
			}
		})
	}
}

func TestHealthRequiresVersionAndLicensedEdition(t *testing.T) {
	health := map[string]string{"status": "healthy", "version": "1.0.1", "build_tier": "professional", "effective_tier": "professional"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(health) }))
	defer server.Close()
	daemon := ReleaseDaemon{Config: UpdaterConfig{HealthURL: server.URL}}
	if err := daemon.waitHealthy(context.Background(), 20*time.Millisecond, "1.0.2", "professional"); err == nil {
		t.Fatal("old process passed new release health check")
	}
	health["version"] = "1.0.2"
	health["effective_tier"] = "community"
	if err := daemon.waitHealthy(context.Background(), 20*time.Millisecond, "1.0.2", "professional"); err == nil {
		t.Fatal("unlicensed paid build passed health check")
	}
	health["effective_tier"] = "professional"
	if err := daemon.waitHealthy(context.Background(), time.Second, "1.0.2", "professional"); err != nil {
		t.Fatal(err)
	}
}

func TestStatusDoesNotBlockOnOperationLock(t *testing.T) {
	daemon := ReleaseDaemon{Config: UpdaterConfig{StatePath: filepath.Join(t.TempDir(), "state.json")}}
	daemon.mu.Lock()
	defer daemon.mu.Unlock()
	done := make(chan UpdaterResponse, 1)
	go func() { done <- daemon.Execute(context.Background(), UpdaterRequest{Operation: "status"}) }()
	select {
	case response := <-done:
		if !response.OK {
			t.Fatal(response.Error)
		}
	case <-time.After(time.Second):
		t.Fatal("status blocked on an updater job")
	}
}

func TestCorruptJournalPreventsUpgrade(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	if err := os.WriteFile(statePath, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	daemon := ReleaseDaemon{Config: UpdaterConfig{StatePath: statePath}}
	if _, err := daemon.loadState(); err == nil {
		t.Fatal("corrupt journal was treated as idle")
	}
	if response := daemon.failure(errors.New("job failed")); response.Error == "" {
		t.Fatal("corrupt failure journal was accepted")
	}
	data, err := os.ReadFile(statePath)
	if err != nil || string(data) != "corrupt" {
		t.Fatal("recording failure overwrote the corrupt recovery journal")
	}
}

func TestAtomicWriteFailurePreservesOldFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "state.json")
	if err := writeAtomicFile(target, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomicFile(filepath.Join(target, "invalid"), []byte("new"), 0600); err == nil {
		t.Fatal("invalid write succeeded")
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "old" {
		t.Fatal("failed write altered existing state")
	}
}
