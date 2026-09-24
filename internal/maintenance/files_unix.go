//go:build !windows

package maintenance

import "os"

func replaceFile(source, destination string) error { return os.Rename(source, destination) }
