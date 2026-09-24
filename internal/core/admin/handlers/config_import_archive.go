package handlers

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	maxConfigImportBytes  = 20 << 20
	maxConfigArchiveFiles = 4096
)

type configArchive struct {
	configData []byte
	files      map[string][]byte
	hasRules   bool
	hasConfig  bool
}

func isConfigArchive(data []byte) bool {
	return len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b
}

func readConfigArchive(data []byte) (configArchive, error) {
	archive := configArchive{files: make(map[string][]byte)}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return archive, fmt.Errorf("invalid configuration archive: %w", err)
	}
	defer gz.Close()

	reader := tar.NewReader(io.LimitReader(gz, maxConfigImportBytes+1))
	var total int64
	entries := 0
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return archive, fmt.Errorf("read configuration archive: %w", err)
		}
		entries++
		if entries > maxConfigArchiveFiles {
			return archive, fmt.Errorf("configuration archive has too many files")
		}

		name, err := safeConfigArchivePath(header.Name)
		if err != nil {
			return archive, err
		}
		if header.Typeflag == tar.TypeDir {
			if name == "rules" || strings.HasPrefix(name, "rules/") || name == "data/rules" || strings.HasPrefix(name, "data/rules/") {
				archive.hasRules = true
			}
			if name == "config" || strings.HasPrefix(name, "config/") {
				archive.hasConfig = true
			}
			continue
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			return archive, fmt.Errorf("configuration archive contains unsupported entry %q", header.Name)
		}
		if name == "rules" || name == "data/rules" || name == "config" || (name != "config.yaml" && name != "manifest.json" && !isYAMLFile(filepath.FromSlash(name))) {
			return archive, fmt.Errorf("configuration archive contains unsupported entry %q", header.Name)
		}
		if header.Size < 0 || header.Size > maxConfigImportBytes || total+header.Size > maxConfigImportBytes {
			return archive, fmt.Errorf("configuration archive exceeds the %d MB limit", maxConfigImportBytes>>20)
		}
		if _, exists := archive.files[name]; exists {
			return archive, fmt.Errorf("configuration archive contains duplicate entry %q", name)
		}

		contents, err := io.ReadAll(io.LimitReader(reader, header.Size+1))
		if err != nil {
			return archive, fmt.Errorf("read archive entry %q: %w", name, err)
		}
		if int64(len(contents)) != header.Size {
			return archive, fmt.Errorf("archive entry %q is truncated", name)
		}
		total += int64(len(contents))
		archive.files[name] = contents
		if name == "config.yaml" {
			archive.configData = contents
		}
		if name == "rules" || strings.HasPrefix(name, "rules/") || name == "data/rules" || strings.HasPrefix(name, "data/rules/") {
			archive.hasRules = true
		}
		if name == "config" || strings.HasPrefix(name, "config/") {
			archive.hasConfig = true
		}
	}
	if len(archive.configData) == 0 {
		return archive, fmt.Errorf("configuration archive does not contain config.yaml")
	}
	return archive, nil
}

func safeConfigArchivePath(raw string) (string, error) {
	normalized := strings.ReplaceAll(raw, "\\", "/")
	if strings.HasPrefix(normalized, "/") || filepath.VolumeName(raw) != "" {
		return "", fmt.Errorf("configuration archive contains unsafe path %q", raw)
	}
	for _, part := range strings.Split(normalized, "/") {
		if part == ".." {
			return "", fmt.Errorf("configuration archive contains unsafe path %q", raw)
		}
	}
	name := path.Clean(normalized)
	if name == "." || name == "" || strings.HasPrefix(name, "../") || strings.Contains(name, "/../") {
		return "", fmt.Errorf("configuration archive contains unsafe path %q", raw)
	}
	if name == "manifest.json" || name == "config.yaml" || name == "rules" || name == "config" || strings.HasPrefix(name, "rules/") || strings.HasPrefix(name, "config/") || name == "data/rules" || strings.HasPrefix(name, "data/rules/") {
		return name, nil
	}
	return "", fmt.Errorf("configuration archive contains unsupported path %q", raw)
}

func prepareImportedConfig(data []byte) ([]byte, error) {
	return prepareImportedConfigFromPath(data, "config.yaml")
}

func prepareImportedArchiveFiles(archive *configArchive) error {
	for name, contents := range archive.files {
		if name == "config.yaml" || name == "manifest.json" || !isYAMLFile(filepath.FromSlash(name)) {
			continue
		}
		prepared, err := prepareImportedConfigFromPath(contents, filepath.FromSlash(name))
		if err != nil {
			return fmt.Errorf("prepare archive entry %q: %w", name, err)
		}
		archive.files[name] = prepared
	}
	return nil
}

func prepareImportedConfigFromPath(data []byte, currentPath string) ([]byte, error) {
	if err := validateConfigYAML(data); err != nil {
		return nil, err
	}
	if !containsRedactedConfigValue(data) {
		return data, nil
	}

	currentData, err := os.ReadFile(currentPath)
	if err != nil {
		return nil, fmt.Errorf("sanitized configuration imports require the current %s to preserve secret values", filepath.ToSlash(currentPath))
	}
	var incoming, current map[string]interface{}
	if err := yaml.Unmarshal(data, &incoming); err != nil {
		return nil, fmt.Errorf("invalid YAML: %w", err)
	}
	if err := yaml.Unmarshal(currentData, &current); err != nil {
		return nil, fmt.Errorf("read current config.yaml: %w", err)
	}
	var unresolved []string
	mergeRedactedConfigValues(incoming, current, "", &unresolved)
	if len(unresolved) > 0 {
		return nil, fmt.Errorf("sanitized configuration import is missing existing values for: %s", strings.Join(unresolved, ", "))
	}
	prepared, err := yaml.Marshal(incoming)
	if err != nil {
		return nil, fmt.Errorf("encode imported configuration: %w", err)
	}
	if err := validateConfigYAML(prepared); err != nil {
		return nil, err
	}
	return prepared, nil
}

func mergeRedactedConfigValues(incoming, current map[string]interface{}, prefix string, unresolved *[]string) {
	for key, value := range incoming {
		pathName := key
		if prefix != "" {
			pathName = prefix + "." + key
		}
		if value == redactedConfigValue {
			currentValue, exists := current[key]
			if !exists || currentValue == redactedConfigValue {
				*unresolved = append(*unresolved, pathName)
				continue
			}
			incoming[key] = currentValue
			continue
		}
		child, ok := value.(map[string]interface{})
		if !ok {
			continue
		}
		currentChild, _ := current[key].(map[string]interface{})
		if currentChild == nil {
			currentChild = map[string]interface{}{}
		}
		mergeRedactedConfigValues(child, currentChild, pathName, unresolved)
	}
}

func restoreConfigArchive(preparedConfig []byte, archive configArchive) error {
	stage, err := os.MkdirTemp(".", ".aegis-config-restore-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)

	if err := os.WriteFile(filepath.Join(stage, "config.yaml"), preparedConfig, 0o600); err != nil {
		return err
	}
	if archive.hasRules {
		if err := os.MkdirAll(filepath.Join(stage, "data", "rules"), 0o700); err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Join(stage, "rules"), 0o700); err != nil {
			return err
		}
	}
	if archive.hasConfig {
		if err := os.MkdirAll(filepath.Join(stage, "config"), 0o700); err != nil {
			return err
		}
	}
	for name, contents := range archive.files {
		if name == "config.yaml" || name == "manifest.json" {
			continue
		}
		target := filepath.Join(stage, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(target, contents, 0o600); err != nil {
			return err
		}
	}

	backupRoot, err := os.MkdirTemp(".", ".aegis-config-restore-backup-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(backupRoot)

	targets := []string{"config.yaml"}
	if archive.hasRules {
		if _, err := os.Stat("data/rules"); err == nil {
			targets = append(targets, filepath.Join("data", "rules"))
		}
		if _, err := os.Stat("rules"); err == nil {
			targets = append(targets, "rules")
		}
	}
	if archive.hasConfig {
		targets = append(targets, "config")
	}
	backedUp := make([]string, 0, len(targets))
	applied := make([]string, 0, len(targets))
	rollback := func() {
		for index := len(applied) - 1; index >= 0; index-- {
			_ = os.RemoveAll(applied[index])
		}
		for index := len(backedUp) - 1; index >= 0; index-- {
			target := backedUp[index]
			_ = os.Rename(filepath.Join(backupRoot, target), target)
		}
	}
	for _, target := range targets {
		if _, err := os.Lstat(target); err == nil {
			backupTarget := filepath.Join(backupRoot, target)
			if err := os.MkdirAll(filepath.Dir(backupTarget), 0o700); err != nil {
				rollback()
				return err
			}
			if err := os.Rename(target, backupTarget); err != nil {
				rollback()
				return err
			}
			backedUp = append(backedUp, target)
		} else if !os.IsNotExist(err) {
			rollback()
			return err
		}

		if err := os.Rename(filepath.Join(stage, target), target); err != nil {
			rollback()
			return err
		}
		applied = append(applied, target)
	}
	return nil
}
