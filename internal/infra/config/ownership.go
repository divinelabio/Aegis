package config

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// ConfigurationOwner identifies the durable authority for a configuration
// subtree. Bootstrap values must be available before PostgreSQL can be opened;
// control-plane values will move to PostgreSQL in later migration phases.
type ConfigurationOwner string

const (
	ConfigurationOwnerBootstrap    ConfigurationOwner = "bootstrap"
	ConfigurationOwnerControlPlane ConfigurationOwner = "control_plane"
)

// ConfigurationOwnership records an intentional ownership decision for one
// root key in Config. Keeping this list alongside the Go configuration model
// makes a newly added root fail validation until its persistence boundary is
// chosen explicitly.
type ConfigurationOwnership struct {
	Path  string
	Owner ConfigurationOwner
}

var configurationOwnershipRegistry = []ConfigurationOwnership{
	{Path: "access", Owner: ConfigurationOwnerControlPlane},
	{Path: "access_log", Owner: ConfigurationOwnerBootstrap},
	{Path: "infrastructure", Owner: ConfigurationOwnerControlPlane},
	{Path: "license", Owner: ConfigurationOwnerBootstrap},
	{Path: "log", Owner: ConfigurationOwnerBootstrap},
	{Path: "modules", Owner: ConfigurationOwnerControlPlane},
	{Path: "sections", Owner: ConfigurationOwnerControlPlane},
	{Path: "security_txt", Owner: ConfigurationOwnerControlPlane},
	{Path: "server", Owner: ConfigurationOwnerBootstrap},
	{Path: "storage", Owner: ConfigurationOwnerBootstrap},
	{Path: "telemetry", Owner: ConfigurationOwnerBootstrap},
	{Path: "threat", Owner: ConfigurationOwnerControlPlane},
	{Path: "updater", Owner: ConfigurationOwnerBootstrap},
	{Path: "upstream", Owner: ConfigurationOwnerControlPlane},
}

// RegisteredConfigurationOwners returns a copy so callers cannot mutate the
// registry that guards migration ownership decisions.
func RegisteredConfigurationOwners() []ConfigurationOwnership {
	owners := make([]ConfigurationOwnership, len(configurationOwnershipRegistry))
	copy(owners, configurationOwnershipRegistry)
	return owners
}

// ConfigurationOwnerForPath resolves a complete configuration path to the
// owner of its top-level document. A caller must treat an unknown path as an
// error; falling back to YAML would reintroduce a second source of truth.
func ConfigurationOwnerForPath(path string) (ConfigurationOwner, bool) {
	parts := strings.Split(path, ".")
	if len(parts) == 0 || parts[0] == "" {
		return "", false
	}
	for _, part := range parts {
		if part == "" || strings.TrimSpace(part) != part {
			return "", false
		}
	}
	for _, ownership := range configurationOwnershipRegistry {
		if ownership.Path == parts[0] {
			return ownership.Owner, true
		}
	}
	return "", false
}

func validateConfigurationOwnershipRegistry() error {
	configRoots, err := configRootKeys()
	if err != nil {
		return err
	}

	registered := make(map[string]ConfigurationOwner, len(configurationOwnershipRegistry))
	for _, ownership := range configurationOwnershipRegistry {
		if ownership.Path == "" {
			return fmt.Errorf("configuration ownership registry contains an empty path")
		}
		if ownership.Owner != ConfigurationOwnerBootstrap && ownership.Owner != ConfigurationOwnerControlPlane {
			return fmt.Errorf("configuration root %q has invalid owner %q", ownership.Path, ownership.Owner)
		}
		if _, exists := registered[ownership.Path]; exists {
			return fmt.Errorf("configuration ownership registry contains duplicate root %q", ownership.Path)
		}
		registered[ownership.Path] = ownership.Owner
	}

	for root := range configRoots {
		if _, exists := registered[root]; !exists {
			return fmt.Errorf("configuration root %q has no ownership decision", root)
		}
	}
	for root := range registered {
		if _, exists := configRoots[root]; !exists {
			return fmt.Errorf("configuration ownership registry contains unknown root %q", root)
		}
	}
	return nil
}

func configRootKeys() (map[string]struct{}, error) {
	typeOfConfig := reflect.TypeOf(Config{})
	roots := make(map[string]struct{}, typeOfConfig.NumField())
	for index := 0; index < typeOfConfig.NumField(); index++ {
		field := typeOfConfig.Field(index)
		tag := strings.Split(field.Tag.Get("mapstructure"), ",")[0]
		if tag == "" || tag == "-" {
			return nil, fmt.Errorf("Config.%s must declare a mapstructure root", field.Name)
		}
		if _, exists := roots[tag]; exists {
			return nil, fmt.Errorf("Config declares duplicate mapstructure root %q", tag)
		}
		roots[tag] = struct{}{}
	}
	return roots, nil
}

func sortedConfigurationRoots() ([]string, error) {
	roots, err := configRootKeys()
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(roots))
	for root := range roots {
		keys = append(keys, root)
	}
	sort.Strings(keys)
	return keys, nil
}
