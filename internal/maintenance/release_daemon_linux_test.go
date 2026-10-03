//go:build linux

package maintenance

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func systemctlFixture(t *testing.T) (string, string) {
	t.Helper()
	directory := t.TempDir()
	logPath := filepath.Join(directory, "commands.log")
	limitPath := filepath.Join(directory, "start-limit-hit")
	script := `#!/bin/sh
printf '%s\n' "$*" >> "$AEGIS_TEST_SYSTEMCTL_LOG"
case "$1" in
  reset-failed)
    if [ "$AEGIS_TEST_RESET_FAILURE" = 1 ]; then
      printf 'reset denied\n' >&2
      exit 1
    fi
    : > "$AEGIS_TEST_LIMIT_RESET"
    ;;
  restart)
    if [ ! -f "$AEGIS_TEST_LIMIT_RESET" ]; then
      printf 'Start request repeated too quickly\n' >&2
      exit 1
    fi
    if [ "$AEGIS_TEST_RESTART_FAILURE" = 1 ]; then
      printf 'candidate startup failed\n' >&2
      exit 1
    fi
    ;;
  *) exit 2 ;;
esac
`
	if err := os.WriteFile(filepath.Join(directory, "systemctl"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory)
	t.Setenv("AEGIS_TEST_SYSTEMCTL_LOG", logPath)
	t.Setenv("AEGIS_TEST_LIMIT_RESET", limitPath)
	t.Setenv("AEGIS_TEST_RESET_FAILURE", "")
	t.Setenv("AEGIS_TEST_RESTART_FAILURE", "")
	return logPath, limitPath
}

func TestManagedRestartClearsStartLimitForOnlyConfiguredUnit(t *testing.T) {
	logPath, _ := systemctlFixture(t)
	if err := restartService(context.Background(), "aegis.service"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(logPath)
	if err != nil || string(data) != "reset-failed -- aegis.service\nrestart -- aegis.service\n" {
		t.Fatalf("unexpected reset/restart commands: %q %v", data, err)
	}
}

func TestManagedRestartStopsIfStartLimitResetFails(t *testing.T) {
	logPath, _ := systemctlFixture(t)
	t.Setenv("AEGIS_TEST_RESET_FAILURE", "1")
	err := restartService(context.Background(), "aegis.service")
	if err == nil || !strings.Contains(err.Error(), "reset denied") {
		t.Fatalf("reset failure was hidden: %v", err)
	}
	data, _ := os.ReadFile(logPath)
	if string(data) != "reset-failed -- aegis.service\n" {
		t.Fatalf("restart ran after failed reset: %q", data)
	}
}

func TestManagedRestartRetainsCandidateFailureDiagnosis(t *testing.T) {
	systemctlFixture(t)
	t.Setenv("AEGIS_TEST_RESTART_FAILURE", "1")
	err := restartService(context.Background(), "aegis.service")
	if err == nil || !strings.Contains(err.Error(), "candidate startup failed") {
		t.Fatalf("restart failure diagnosis was hidden: %v", err)
	}
}

func TestCancelledManagedRestartDoesNotExecuteSystemctl(t *testing.T) {
	logPath, _ := systemctlFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := restartService(ctx, "aegis.service"); err == nil {
		t.Fatal("canceled managed restart succeeded")
	}
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Fatalf("systemctl executed after cancellation: %v", err)
	}
}

func TestManagedRestartRejectsGlobalResetTargets(t *testing.T) {
	logPath, _ := systemctlFixture(t)
	for _, name := range []string{"", "*.service", "aegis?.service", "aegis.service other.service"} {
		if err := restartService(context.Background(), name); err == nil {
			t.Fatalf("non-specific service name %q was accepted", name)
		}
	}
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Fatalf("systemctl executed for a non-specific service name: %v", err)
	}
}
