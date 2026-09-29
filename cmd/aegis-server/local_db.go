package main

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

// ensureLocalPostgres checks if PostgreSQL is required on localhost and not running.
// If a local data/pgdata directory exists, it auto-cleans stale PID files, starts
// PostgreSQL via pg_ctl, and waits until the port is open before proceeding.
func ensureLocalPostgres(logger *zap.Logger, host string, port int) {
	if host != "127.0.0.1" && host != "localhost" {
		return
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
	if err == nil {
		conn.Close()
		return
	}

	// Look for local data/pgdata
	candidates := []string{
		"data/pgdata",
		"data\\pgdata",
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "data", "pgdata"))
	}

	var pgData string
	for _, cand := range candidates {
		if fi, err := os.Stat(cand); err == nil && fi.IsDir() {
			pgData = cand
			break
		}
	}
	if pgData == "" {
		return
	}

	logger.Info("PostgreSQL is not responding; checking local database cluster...", zap.String("pgdata", pgData))

	// Clean stale postmaster.pid if process is not running
	pidFile := filepath.Join(pgData, "postmaster.pid")
	if data, err := os.ReadFile(pidFile); err == nil {
		lines := strings.Split(string(data), "\n")
		if len(lines) > 0 {
			if pid, err := strconv.Atoi(strings.TrimSpace(lines[0])); err == nil {
				if !isProcessAlive(pid) {
					logger.Info("Cleaning stale postmaster.pid", zap.Int("stale_pid", pid))
					_ = os.Remove(pidFile)
				} else {
					logger.Info("Waiting for existing PostgreSQL process to accept connections...", zap.Int("pid", pid))
				}
			}
		}
	}

	// Find pg_ctl
	pgCtl := findPgCtlExecutable()
	if pgCtl == "" {
		logger.Warn("pg_ctl executable not found; start PostgreSQL manually if not using an external database")
		return
	}

	logFile := filepath.Join(pgData, "postgres.log")
	logger.Info("Starting local PostgreSQL control-plane database...", zap.String("pg_ctl", pgCtl))
	cmd := exec.Command(pgCtl, "-D", pgData, "-l", logFile, "start")
	if err := cmd.Start(); err != nil {
		logger.Warn("Failed to start PostgreSQL via pg_ctl", zap.Error(err))
	} else {
		_ = cmd.Wait()
	}

	// Poll until ready or timeout (up to 40 seconds for cold/crash-recovery starts)
	deadline := time.Now().Add(40 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)
		conn, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
		if err == nil {
			conn.Close()
			logger.Info("Local PostgreSQL database is ready and accepting connections", zap.String("addr", addr))
			return
		}
	}

	logger.Warn("Timed out waiting for PostgreSQL to open port", zap.String("addr", addr))
}

func findPgCtlExecutable() string {
	if p, err := exec.LookPath("pg_ctl"); err == nil {
		return p
	}

	if runtime.GOOS == "windows" {
		commonPaths := []string{
			`C:\Program Files\PostgreSQL\18\bin\pg_ctl.exe`,
			`C:\Program Files\PostgreSQL\17\bin\pg_ctl.exe`,
			`C:\Program Files\PostgreSQL\16\bin\pg_ctl.exe`,
			`C:\Program Files\PostgreSQL\15\bin\pg_ctl.exe`,
		}
		for _, p := range commonPaths {
			if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
				return p
			}
		}
	}

	return ""
}
