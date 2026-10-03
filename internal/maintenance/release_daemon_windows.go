//go:build windows

package maintenance

import (
	"context"
	"errors"
	"github.com/Microsoft/go-winio"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

func (d *ReleaseDaemon) Serve(ctx context.Context) error {
	if err := validateUpdaterConfig(d.Config); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(d.Config.StatePath), 0700); err != nil {
		return err
	}
	lock, err := os.OpenFile(d.Config.StatePath+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	var overlapped windows.Overlapped
	if err := windows.LockFileEx(windows.Handle(lock.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped); err != nil {
		return errors.New("another updater owns this state directory")
	}
	defer windows.UnlockFileEx(windows.Handle(lock.Fd()), 0, 1, 0, &overlapped)
	defer d.stopJobs()
	if err := d.recoverInterrupted(ctx); err != nil {
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

// Atomic journal replacement uses MOVEFILE_WRITE_THROUGH on Windows.
func syncReleaseDirectory(string) error { return nil }
func restartService(ctx context.Context, name string) error {
	if strings.HasPrefix(name, "task:") {
		command := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", `$ErrorActionPreference='Stop'; $task=Get-ScheduledTask -TaskName $env:AEGIS_UPDATER_TASK_NAME; Stop-ScheduledTask -InputObject $task; $deadline=(Get-Date).AddSeconds(60); while ((Get-ScheduledTask -TaskName $env:AEGIS_UPDATER_TASK_NAME).State -eq 'Running') { if ((Get-Date) -gt $deadline) { throw 'Aegis task did not stop' }; Start-Sleep -Milliseconds 250 }; Start-ScheduledTask -InputObject $task`)
		command.Env = append(os.Environ(), "AEGIS_UPDATER_TASK_NAME="+strings.TrimPrefix(name, "task:"))
		return command.Run()
	}
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
	// Windows cannot replace an existing directory link with MoveFileEx. Keep
	// the old link until its replacement exists, and restore it on rename failure.
	backup := link + ".previous-link"
	if err := os.Remove(backup); err != nil && !os.IsNotExist(err) {
		return err
	}
	if _, err := os.Lstat(link); err == nil {
		if err = os.Rename(link, backup); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(temporary, link); err != nil {
		if _, statErr := os.Lstat(backup); statErr == nil {
			_ = os.Rename(backup, link)
		}
		return err
	}
	_ = os.Remove(backup)
	return nil
}
