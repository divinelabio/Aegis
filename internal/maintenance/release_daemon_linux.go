//go:build linux

package maintenance

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func (d *ReleaseDaemon) Serve(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return errors.New("aegis-updater serve must run as root")
	}
	if err := validateUpdaterConfig(d.Config); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(d.Config.StatePath), 0700); err != nil {
		return err
	}
	if err := validateStateStorage(d.Config.StatePath); err != nil {
		return err
	}
	lock, err := os.OpenFile(d.Config.StatePath+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return errors.New("another updater owns this state directory")
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	defer d.stopJobs()
	if err := d.recoverInterrupted(ctx); err != nil {
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

// State is a root trust boundary: ownership of the journal itself is not
// sufficient when an unprivileged process can replace it through its parent.
func validateStateStorage(statePath string) error {
	for directory := filepath.Dir(statePath); ; directory = filepath.Dir(directory) {
		info, err := os.Lstat(directory)
		if err != nil {
			return err
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
			return errors.New("updater state ancestors must be root-owned directories without group or world write permission; use scripts/migrate-native-updater.sh for legacy installations")
		}
		if directory == filepath.Dir(directory) {
			break
		}
	}
	for _, name := range []string{statePath, statePath + ".lock"} {
		info, err := os.Lstat(name)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return errors.New("updater journal and lock must be root-owned regular files with owner-only permissions")
		}
	}
	return nil
}

func dialUpdater(ctx context.Context, socket string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "unix", socket)
}
func restartService(ctx context.Context, name string) error {
	if name == "" || strings.ContainsAny(name, "*?[]/\x00 \t\r\n") {
		return errors.New("managed restart requires one explicit service unit name")
	}
	// This is an explicit, bounded release transition, including restoration of
	// a known working release. Earlier starts/crashes must not exhaust systemd's
	// rate limit and prevent the updater from bringing that release back up.
	// Reset only the configured unit; its normal automatic restart policy stays
	// in effect, and the release journal retains the original failure diagnosis.
	if err := fixedCommand(ctx, "systemctl", "reset-failed", "--", name); err != nil {
		return fmt.Errorf("reset managed service start limit: %w", err)
	}
	return fixedCommand(ctx, "systemctl", "restart", "--", name)
}
func atomicSymlink(target, link string) error {
	if err := os.MkdirAll(filepath.Dir(link), 0755); err != nil {
		return err
	}
	temporary := link + ".new"
	if err := os.Remove(temporary); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Symlink(target, temporary); err != nil {
		return err
	}
	if err := os.Rename(temporary, link); err != nil {
		return err
	}
	return syncReleaseDirectory(filepath.Dir(link))
}

func syncReleaseDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
func secureRelease(root string) error {
	if err := os.Chmod(root, 0755); err != nil {
		return err
	}
	group, err := user.LookupGroup("aegis")
	if err != nil {
		return nil
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		return err
	}
	return filepath.Walk(root, func(name string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Chown(name, 0, gid)
	})
}
