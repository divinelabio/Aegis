package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/divinelabio/aegis/internal/buildinfo"
	"github.com/divinelabio/aegis/internal/maintenance"
)

var (
	Version               = "1.0.1"
	BuildDate             = "unknown"
	ArtifactRootPublicKey = buildinfo.RootPublicKey
	ArtifactSignedKeySet  = buildinfo.SignedKeySet
	ArtifactIssuer        = buildinfo.LicenseIssuer
	ArtifactAudience      = "aegis-updater"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	command := os.Args[1]
	if command == "version" {
		fmt.Printf("aegis-updater %s (%s)\n", Version, BuildDate)
		return
	}
	flags := flag.NewFlagSet(command, flag.ExitOnError)
	configPath := flags.String("config", "config.yaml", "path to Aegis configuration")
	manifestPath := flags.String("manifest-file", "", "signed artifact manifest file")
	credentialPath := flags.String("credential-file", "", "short-lived artifact credential file")
	_ = flags.Parse(os.Args[2:])
	cfg, err := maintenance.LoadConfig(*configPath)
	if err != nil {
		fatal(err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	switch command {
	case "serve":
		// Validate signer certificates for every upgrade, allowing status and
		// rollback to remain available if the embedded signer has expired.
		daemon := maintenance.ReleaseDaemon{Config: cfg.Updater, Version: Version, Verifier: maintenance.ManifestVerifier{Issuer: ArtifactIssuer, Audience: ArtifactAudience, RootPublicKey: ArtifactRootPublicKey, SignedKeySet: ArtifactSignedKeySet}}
		err = daemon.Serve(ctx)
	case "status":
		var response maintenance.UpdaterResponse
		response, err = maintenance.CallUpdater(ctx, cfg.Updater.SocketPath, maintenance.UpdaterRequest{Operation: "status"})
		if err == nil {
			fmt.Printf("state=%s edition=%s version=%s error=%s\n", response.Status.State, response.Status.Edition, response.Status.Version, response.Status.LastError)
		}
	case "apply":
		if *manifestPath == "" {
			err = fmt.Errorf("--manifest-file is required")
			break
		}
		var manifest, credential []byte
		manifest, err = os.ReadFile(*manifestPath)
		if err != nil {
			break
		}
		if *credentialPath != "" {
			credential, err = os.ReadFile(*credentialPath)
			if err != nil {
				break
			}
		}
		_, err = maintenance.CallUpdater(ctx, cfg.Updater.SocketPath, maintenance.UpdaterRequest{Operation: "upgrade", Manifest: string(manifest), Credential: string(credential)})
	case "rollback":
		_, err = maintenance.CallUpdater(ctx, cfg.Updater.SocketPath, maintenance.UpdaterRequest{Operation: "rollback"})
	case "proxies":
		err = maintenance.UpdateProxies(ctx, cfg)
	case "geo":
		err = maintenance.UpdateGeo(ctx, cfg)
	case "all":
		if err = maintenance.UpdateGeo(ctx, cfg); err == nil {
			err = maintenance.UpdateProxies(ctx, cfg)
		}
	case "version":
		fmt.Printf("aegis-updater %s (%s)\n", Version, BuildDate)
		return
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fatal(err)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "Usage: aegis-updater <serve|status|apply|rollback|geo|proxies|all|version> [flags]")
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "aegis-updater:", err)
	os.Exit(1)
}
