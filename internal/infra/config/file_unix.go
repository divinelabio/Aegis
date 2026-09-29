//go:build !windows

package config

import "os"

func replaceFileAtomic(source, target string) error {
	return os.Rename(source, target)
}
