package config

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// LoadEnvFile reads key=value pairs from the specified file and sets them in
// the process environment if not already set. Lines starting with '#' and empty
// lines are ignored. Values may be single or double quoted.
func LoadEnvFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		if key == "" {
			continue
		}

		val := strings.TrimSpace(parts[1])
		// Strip enclosing quotes if present
		if len(val) >= 2 {
			if (strings.HasPrefix(val, "\"") && strings.HasSuffix(val, "\"")) ||
				(strings.HasPrefix(val, "'") && strings.HasSuffix(val, "'")) {
				val = val[1 : len(val)-1]
			}
		}

		// Don't overwrite existing environment variables (12-factor standard)
		if _, exists := os.LookupEnv(key); !exists {
			_ = os.Setenv(key, val)
		}
	}
	return scanner.Err()
}

// AutoLoadEnv attempts to discover and load an environment file in standard locations:
// 1. Path from AEGIS_ENV environment variable
// 2. aegis.env in current working directory
// 3. .env in current working directory
// 4. aegis.env in the directory containing the running executable
// 5. /etc/aegis/aegis.env (on Linux/Unix)
func AutoLoadEnv() {
	if custom := os.Getenv("AEGIS_ENV"); custom != "" {
		if err := LoadEnvFile(custom); err == nil {
			return
		}
	}

	candidates := []string{
		"aegis.env",
		".env",
	}

	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(exeDir, "aegis.env"),
			filepath.Join(exeDir, ".env"),
		)
	}

	candidates = append(candidates, "/etc/aegis/aegis.env")

	for _, candidate := range candidates {
		if fi, err := os.Stat(candidate); err == nil && !fi.IsDir() {
			if err := LoadEnvFile(candidate); err == nil {
				return
			}
		}
	}
}
