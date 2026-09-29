package maintenance

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Updater  UpdaterConfig `yaml:"updater"`
	Sections struct {
		TrafficControl struct {
			Geo struct {
				DBPath string `yaml:"db_path"`
			} `yaml:"geo"`
		} `yaml:"traffic_control"`
	} `yaml:"sections"`
	Infrastructure struct {
		TrustedProxies struct {
			CIDRs        []string `yaml:"cidrs"`
			SourceURLs   []string `yaml:"source_urls"`
			SourceFiles  []string `yaml:"source_files"`
			SourceRoot   string   `yaml:"source_root"`
			CombinedList string   `yaml:"combined_list"`
		} `yaml:"trusted_proxies"`
	} `yaml:"infrastructure"`
}

type UpdaterConfig struct {
	SocketPath       string `yaml:"socket_path"`
	StatePath        string `yaml:"state_path"`
	ReleasesRoot     string `yaml:"releases_root"`
	CurrentLink      string `yaml:"current_link"`
	ServiceName      string `yaml:"service_name"`
	HealthURL        string `yaml:"health_url"`
	Mode             string `yaml:"mode"`
	ComposePath      string `yaml:"compose_path"`
	ComposeService   string `yaml:"compose_service"`
	ReleaseEnvPath   string `yaml:"release_env_path"`
	ContainerRuntime string `yaml:"container_runtime"`
}

func LoadConfig(path string) (Config, error) {
	var cfg Config
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	base := filepath.Dir(path)
	if runtime.GOOS == "windows" {
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = base
		}
		if !strings.HasPrefix(strings.ToLower(cfg.Updater.SocketPath), `\\.\pipe\`) {
			cfg.Updater.SocketPath = `\\.\pipe\aegis-updater`
		}
		cfg.Updater.StatePath = resolvePath(programData, cfg.Updater.StatePath, "Aegis/updater-state.json")
		cfg.Updater.ReleasesRoot = resolvePath(programData, cfg.Updater.ReleasesRoot, "Aegis/releases")
		cfg.Updater.CurrentLink = resolvePath(programData, cfg.Updater.CurrentLink, "Aegis/current")
		cfg.Updater.ReleaseEnvPath = resolvePath(programData, cfg.Updater.ReleaseEnvPath, "Aegis/release.env")
	} else {
		cfg.Updater.SocketPath = resolvePath(base, cfg.Updater.SocketPath, "/run/aegis/updater.sock")
		cfg.Updater.StatePath = resolvePath(base, cfg.Updater.StatePath, "/var/lib/aegis/updater-state.json")
		cfg.Updater.ReleasesRoot = resolvePath(base, cfg.Updater.ReleasesRoot, "/opt/aegis/releases")
		cfg.Updater.CurrentLink = resolvePath(base, cfg.Updater.CurrentLink, "/opt/aegis/current")
		cfg.Updater.ReleaseEnvPath = resolvePath(base, cfg.Updater.ReleaseEnvPath, "/etc/aegis/release.env")
	}
	if cfg.Updater.ServiceName == "" {
		cfg.Updater.ServiceName = "aegis.service"
	}
	if cfg.Updater.HealthURL == "" {
		cfg.Updater.HealthURL = "http://127.0.0.1:8080/health"
	}
	if cfg.Updater.Mode == "" {
		cfg.Updater.Mode = "native"
	}
	if cfg.Updater.ComposeService == "" {
		cfg.Updater.ComposeService = "aegis"
	}
	if cfg.Updater.ContainerRuntime == "" {
		cfg.Updater.ContainerRuntime = "docker"
	}
	cfg.Sections.TrafficControl.Geo.DBPath = resolvePath(base, cfg.Sections.TrafficControl.Geo.DBPath, "data/dbip-country.mmdb")
	tp := &cfg.Infrastructure.TrustedProxies
	tp.SourceRoot = resolvePath(base, tp.SourceRoot, "data/trusted-proxies/sources")
	tp.CombinedList = resolvePath(base, tp.CombinedList, "data/trusted-proxies/combined.list")
	return cfg, nil
}

func resolvePath(base, value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		value = fallback
	}
	if filepath.IsAbs(value) {
		return filepath.Clean(value)
	}
	return filepath.Clean(filepath.Join(base, value))
}
