package main

import (
	"context"
	"github.com/divinelabio/aegis/internal/maintenance"
	"runtime"
	"time"
)

func configuredUpdaterVersion(cfg interface{}) func(context.Context) string {
	socket := "/run/aegis/updater.sock"
	if runtime.GOOS == "windows" {
		socket = `\\.\pipe\aegis-updater`
	}
	if settings, ok := cfg.(interface{ GetUpdaterSocket() string }); ok && settings.GetUpdaterSocket() != "" {
		socket = settings.GetUpdaterSocket()
	}
	return func(ctx context.Context) string {
		probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		response, err := maintenance.CallUpdater(probeCtx, socket, maintenance.UpdaterRequest{Operation: "status"})
		if err != nil {
			return ""
		}
		return response.UpdaterVersion
	}
}

func configuredArtifactFormat(cfg interface{}) string {
	if settings, ok := cfg.(interface{ GetUpdaterMode() string }); ok && settings.GetUpdaterMode() == "docker" {
		return "docker.tar.gz"
	}
	if runtime.GOOS == "windows" {
		return "zip"
	}
	return "tar.gz"
}
