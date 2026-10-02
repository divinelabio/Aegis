//go:build windows

package maintenance

import (
	"context"
	"errors"
	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (d *ReleaseDaemon) Serve(ctx context.Context) error {
	if err := d.recoverInterrupted(ctx); err != nil {
		return err
	}
	if err := validateUpdaterConfig(d.Config); err != nil {
		return err
	}
	listener, err := winio.ListenPipe(d.Config.SocketPath, &winio.PipeConfig{
		SecurityDescriptor: "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)",
		InputBufferSize:    64 << 10, OutputBufferSize: 64 << 10,
	})
	if err != nil {
		return err
	}
	defer listener.Close()
	go func() { <-ctx.Done(); _ = listener.Close() }()
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

func dialUpdater(ctx context.Context, pipe string) (net.Conn, error) {
	return winio.DialPipeContext(ctx, pipe)
}
func secureRelease(root string) error { return nil }
func restartService(ctx context.Context, name string) error {
	_ = fixedCommand(ctx, "sc.exe", "stop", name)
	for attempt := 0; attempt < 60; attempt++ {
		out, err := commandOutput(ctx, "sc.exe", "query", name)
		if err != nil {
			return err
		}
		if strings.Contains(out, "STOPPED") {
			return fixedCommand(ctx, "sc.exe", "start", name)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return errors.New("service did not stop within 60 seconds")
}
func atomicSymlink(target, link string) error {
	if err := os.MkdirAll(filepath.Dir(link), 0755); err != nil {
		return err
	}
	temporary := link + ".new"
	_ = os.Remove(temporary)
	if err := os.Symlink(target, temporary); err != nil {
		return err
	}
	source, err := windows.UTF16PtrFromString(temporary)
	if err != nil {
		return err
	}
	destination, err := windows.UTF16PtrFromString(link)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(source, destination, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
