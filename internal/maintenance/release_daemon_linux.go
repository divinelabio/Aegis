//go:build linux

package maintenance

import (
	"context"
	"errors"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
)

func (d *ReleaseDaemon) Serve(ctx context.Context) error {
	if err := d.recoverInterrupted(ctx); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("aegis-updater serve must run as root")
	}
	if err := validateUpdaterConfig(d.Config); err != nil {
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

func dialUpdater(ctx context.Context, socket string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "unix", socket)
}
func restartService(ctx context.Context, name string) error {
	return fixedCommand(ctx, "systemctl", "restart", name)
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
	return os.Rename(temporary, link)
}
func replaceFile(source, destination string) error { return os.Rename(source, destination) }
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
