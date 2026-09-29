// aegisctl is the operator command line for a running Aegis installation.
// Runtime mutations use the protected Admin API; only identity recovery uses
// the local PostgreSQL control plane when an administrator cannot sign in.
package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/divinelab-io/aegis/internal/infra/config"
	"github.com/divinelab-io/aegis/internal/maintenance"
	"github.com/divinelab-io/aegis/internal/operatorcli"
)

var (
	Version   = "dev"
	BuildDate = "unknown"
)

type options struct {
	configPath    string
	adminURL      string
	username      string
	passwordFile  string
	mfaFile       string
	passwordStdin bool
	mfaStdin      bool
	output        string
	force         bool
	yes           bool
	confirm       string
	timeout       time.Duration
}

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "aegisctl:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	opts, command, rest, err := parseOptions(args, stderr)
	if err != nil {
		return err
	}
	switch command {
	case "help", "--help", "-h", "":
		usage(stdout)
		return nil
	case "version":
		return writeJSON(stdout, map[string]string{"component": "aegisctl", "version": Version, "build_date": BuildDate})
	case "status", "health":
		client, err := operatorcli.NewClient(opts.adminURL, opts.timeout)
		if err != nil {
			return err
		}
		data, err := client.Request(ctx, http.MethodGet, "/api/health", nil, "")
		if err != nil {
			return err
		}
		return writeResponse(stdout, data)
	case "doctor":
		return runDoctor(ctx, opts, stdout)
	case "user":
		return runUser(ctx, opts, rest, stdin, stdout)
	case "mfa":
		return runMFA(ctx, opts, rest, stdout)
	case "license":
		return runLicense(ctx, opts, rest, stdin, stdout)
	case "config":
		return runConfig(ctx, opts, rest, stdin, stdout)
	case "backup":
		return runBackup(ctx, opts, rest, stdin, stdout)
	case "system":
		return runSystem(ctx, opts, rest, stdin, stdout)
	case "tls":
		return runTLS(ctx, opts, rest, stdin, stdout, stderr)
	case "section":
		return runSection(ctx, opts, rest, stdin, stdout)
	case "waf":
		return runWAF(ctx, opts, rest, stdin, stdout)
	case "events":
		return runEvents(ctx, opts, rest, stdin, stdout, stderr)
	case "logs":
		return runLogs(ctx, opts, rest, stdin, stdout)
	case "support-bundle":
		return runSupportBundle(ctx, opts, rest, stdin, stdout)
	case "update":
		return runUpdate(ctx, opts, rest, stdout)
	default:
		return fmt.Errorf("unknown command %q; run aegisctl help", command)
	}
}

func parseOptions(args []string, stderr io.Writer) (options, string, []string, error) {
	opts := options{configPath: "config.yaml", adminURL: "http://127.0.0.1:8081", timeout: 15 * time.Second}
	remaining := make([]string, 0, len(args))
	value := func(index *int, flagName string) (string, error) {
		if *index+1 >= len(args) {
			return "", fmt.Errorf("%s requires a value", flagName)
		}
		*index = *index + 1
		return args[*index], nil
	}
	for index := 0; index < len(args); index++ {
		arg := args[index]
		var err error
		switch arg {
		case "--config":
			opts.configPath, err = value(&index, arg)
		case "--admin-url":
			opts.adminURL, err = value(&index, arg)
		case "--username":
			opts.username, err = value(&index, arg)
		case "--password-file":
			opts.passwordFile, err = value(&index, arg)
		case "--mfa-file":
			opts.mfaFile, err = value(&index, arg)
		case "--output":
			opts.output, err = value(&index, arg)
		case "--confirm":
			opts.confirm, err = value(&index, arg)
		case "--timeout":
			var raw string
			raw, err = value(&index, arg)
			if err == nil {
				opts.timeout, err = time.ParseDuration(raw)
			}
		case "--password-stdin":
			opts.passwordStdin = true
		case "--mfa-stdin":
			opts.mfaStdin = true
		case "--force":
			opts.force = true
		case "--yes":
			opts.yes = true
		default:
			remaining = append(remaining, arg)
		}
		if err != nil {
			return options{}, "", nil, err
		}
	}
	if opts.username == "" {
		opts.username = strings.TrimSpace(os.Getenv("AEGISCTL_USERNAME"))
	}
	if len(remaining) == 0 {
		return opts, "", nil, nil
	}
	return opts, remaining[0], remaining[1:], nil
}

func runDoctor(ctx context.Context, opts options, stdout io.Writer) error {
	cfg, err := config.LoadControlPlaneConfig(opts.configPath)
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	result := map[string]any{
		"config": map[string]any{
			"path": opts.configPath, "valid": true,
			"admin_host": cfg.Server.Admin.Host, "admin_port": cfg.Server.Admin.Port,
		},
	}
	client, clientErr := operatorcli.NewClient(opts.adminURL, opts.timeout)
	if clientErr == nil {
		data, healthErr := client.Request(ctx, http.MethodGet, "/api/health", nil, "")
		if healthErr == nil {
			var health any
			if json.Unmarshal(data, &health) == nil {
				result["health"] = health
			}
		} else {
			result["health"] = map[string]any{"reachable": false, "error": healthErr.Error()}
		}
	}
	return writeJSON(stdout, result)
}

func runUser(ctx context.Context, opts options, args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: aegisctl user <list|reset-password|enable|disable|revoke-sessions> ...")
	}
	service, closeService, err := operatorcli.OpenIdentity(ctx, opts.configPath)
	if err != nil {
		return fmt.Errorf("open identity recovery service: %w", err)
	}
	defer closeService()
	switch args[0] {
	case "list":
		users, err := service.List(ctx, 100)
		if err != nil {
			return err
		}
		return writeJSON(stdout, users)
	case "reset-password":
		username, passwordArgs, err := commandTarget(args[1:])
		if err != nil {
			return errors.New("usage: aegisctl user reset-password <username> --new-password-stdin")
		}
		password, err := readRequiredSecret(stdin, "AEGISCTL_NEW_PASSWORD", "--new-password-file", passwordArgs, "--new-password-stdin")
		if err != nil {
			return err
		}
		if err := service.ResetPassword(ctx, username, password); err != nil {
			return err
		}
		return writeJSON(stdout, map[string]any{"status": "password_reset", "username": username, "sessions_invalidated": true})
	case "enable", "disable", "revoke-sessions":
		if len(args) != 2 {
			return fmt.Errorf("usage: aegisctl user %s <username> --yes", args[0])
		}
		if !opts.yes {
			return errors.New("this identity mutation requires --yes")
		}
		var actionErr error
		switch args[0] {
		case "enable":
			actionErr = service.SetActive(ctx, args[1], true)
		case "disable":
			actionErr = service.SetActive(ctx, args[1], false)
		case "revoke-sessions":
			actionErr = service.RevokeSessions(ctx, args[1])
		}
		if actionErr != nil {
			return actionErr
		}
		return writeJSON(stdout, map[string]any{"status": args[0], "username": args[1], "sessions_invalidated": true})
	default:
		return fmt.Errorf("unknown user command %q", args[0])
	}
}

func runMFA(ctx context.Context, opts options, args []string, stdout io.Writer) error {
	if len(args) != 2 || args[0] != "reset" {
		return errors.New("usage: aegisctl mfa reset <username> --yes")
	}
	if !opts.yes {
		return errors.New("MFA recovery requires --yes")
	}
	service, closeService, err := operatorcli.OpenIdentity(ctx, opts.configPath)
	if err != nil {
		return fmt.Errorf("open identity recovery service: %w", err)
	}
	defer closeService()
	if err := service.ResetMFA(ctx, args[1]); err != nil {
		return err
	}
	return writeJSON(stdout, map[string]any{"status": "mfa_reset", "username": args[1], "mfa_reenrollment_required": true, "sessions_invalidated": true})
}

func runLicense(ctx context.Context, opts options, args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: aegisctl license <status|activate|refresh|deactivate>")
	}
	client, err := authenticatedClient(ctx, opts, stdin)
	if err != nil {
		return err
	}
	switch args[0] {
	case "status":
		return requestJSON(ctx, client, http.MethodGet, "/api/license", nil, stdout)
	case "activate":
		key, err := readKey(args[1:], stdin, opts.passwordStdin || opts.mfaStdin)
		if err != nil {
			return err
		}
		return requestJSON(ctx, client, http.MethodPost, "/api/license/activate", map[string]string{"key": key}, stdout)
	case "refresh":
		return requestJSON(ctx, client, http.MethodPost, "/api/license/refresh", nil, stdout)
	case "deactivate":
		if !opts.yes {
			return errors.New("licence deactivation requires --yes")
		}
		return requestJSON(ctx, client, http.MethodPost, "/api/license/deactivate", nil, stdout)
	default:
		return fmt.Errorf("unknown licence command %q", args[0])
	}
}

func runConfig(ctx context.Context, opts options, args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: aegisctl config <validate|show|export|backup|apply|restore|reset>")
	}
	switch args[0] {
	case "validate":
		path := opts.configPath
		if len(args) == 2 {
			path = args[1]
		} else if len(args) > 2 {
			return errors.New("usage: aegisctl config validate [path]")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := config.ValidateControlPlaneConfigDocument(data); err != nil {
			return err
		}
		return writeJSON(stdout, map[string]any{"status": "valid", "path": path})
	}
	client, err := authenticatedClient(ctx, opts, stdin)
	if err != nil {
		return err
	}
	switch args[0] {
	case "show":
		return requestJSON(ctx, client, http.MethodGet, "/api/config", nil, stdout)
	case "export":
		data, err := client.Request(ctx, http.MethodGet, "/api/config/export", nil, "")
		if err != nil {
			return err
		}
		return writeArtifact(stdout, opts, data, "aegis-config.yaml")
	case "backup":
		if len(args) != 2 || args[1] != "create" {
			return errors.New("usage: aegisctl config backup create --output <file>")
		}
		data, err := client.Request(ctx, http.MethodGet, "/api/config/backup", nil, "")
		if err != nil {
			return err
		}
		return writeArtifact(stdout, opts, data, "aegis-backup.tar.gz")
	case "apply", "restore":
		if len(args) != 2 {
			return fmt.Errorf("usage: aegisctl config %s <config-or-archive> --yes", args[0])
		}
		if !opts.yes {
			return errors.New("configuration import requires --yes")
		}
		data, err := client.UploadFile(ctx, "/api/config/import", "config", args[1], nil)
		if err != nil {
			return err
		}
		return writeResponse(stdout, data)
	case "reset":
		if opts.confirm != "RESET-CONFIG" {
			return errors.New("configuration reset requires --confirm RESET-CONFIG")
		}
		return requestJSON(ctx, client, http.MethodPost, "/api/config/reset", nil, stdout)
	default:
		return fmt.Errorf("unknown config command %q", args[0])
	}
}

func runBackup(ctx context.Context, opts options, args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: aegisctl backup <create|restore>")
	}
	client, err := authenticatedClient(ctx, opts, stdin)
	if err != nil {
		return err
	}
	switch args[0] {
	case "create":
		if len(args) != 1 {
			return errors.New("usage: aegisctl backup create --output <file>")
		}
		data, err := client.Request(ctx, http.MethodGet, "/api/config/backup", nil, "")
		if err != nil {
			return err
		}
		return writeArtifact(stdout, opts, data, "aegis-backup.tar.gz")
	case "restore":
		if len(args) != 2 {
			return errors.New("usage: aegisctl backup restore <archive> --yes")
		}
		if !opts.yes {
			return errors.New("backup restore requires --yes")
		}
		data, err := client.UploadFile(ctx, "/api/config/import", "config", args[1], nil)
		if err != nil {
			return err
		}
		return writeResponse(stdout, data)
	default:
		return fmt.Errorf("unknown backup command %q", args[0])
	}
}

func runSystem(ctx context.Context, opts options, args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) != 1 || args[0] != "factory-reset" {
		return errors.New("usage: aegisctl system factory-reset --confirm RESET-CONFIG")
	}
	if opts.confirm != "RESET-CONFIG" {
		return errors.New("factory-reset currently resets bootstrap configuration only and requires --confirm RESET-CONFIG")
	}
	client, err := authenticatedClient(ctx, opts, stdin)
	if err != nil {
		return err
	}
	return requestJSON(ctx, client, http.MethodPost, "/api/config/reset", nil, stdout)
}

func runTLS(ctx context.Context, opts options, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: aegisctl tls <status|list|config|upload|delete>")
	}
	client, err := authenticatedClient(ctx, opts, stdin)
	if err != nil {
		return err
	}
	switch args[0] {
	case "status":
		return requestJSON(ctx, client, http.MethodGet, "/api/certificates/config", nil, stdout)
	case "list":
		return requestJSON(ctx, client, http.MethodGet, "/api/certificates", nil, stdout)
	case "config":
		if len(args) < 2 {
			return errors.New("usage: aegisctl tls config <show|apply> [json-file] --yes")
		}
		if args[1] == "show" && len(args) == 2 {
			return requestJSON(ctx, client, http.MethodGet, "/api/certificates/config", nil, stdout)
		}
		if args[1] != "apply" || len(args) != 3 {
			return errors.New("usage: aegisctl tls config apply <json-file> --yes")
		}
		if !opts.yes {
			return errors.New("TLS configuration apply requires --yes")
		}
		return requestRawFile(ctx, client, http.MethodPut, "/api/certificates/config", args[2], stdout)
	case "upload":
		if !opts.yes {
			return errors.New("TLS certificate upload requires --yes")
		}
		flags := flag.NewFlagSet("tls upload", flag.ContinueOnError)
		flags.SetOutput(stderr)
		certPath := flags.String("certificate", "", "certificate PEM path")
		keyPath := flags.String("key", "", "private-key PEM path")
		domain := flags.String("domain", "", "expected certificate hostname")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if *certPath == "" || *keyPath == "" {
			return errors.New("TLS upload requires --certificate and --key")
		}
		data, err := client.UploadCertificate(ctx, *certPath, *keyPath, *domain)
		if err != nil {
			return err
		}
		return writeResponse(stdout, data)
	case "delete":
		if len(args) != 2 {
			return errors.New("usage: aegisctl tls delete <certificate-id> --yes")
		}
		if !opts.yes {
			return errors.New("certificate deletion requires --yes")
		}
		return requestJSON(ctx, client, http.MethodDelete, "/api/certificates", map[string]string{"id": args[1]}, stdout)
	default:
		return fmt.Errorf("unknown TLS command %q", args[0])
	}
}

func runSection(ctx context.Context, opts options, args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: aegisctl section <list|config|test>")
	}
	client, err := authenticatedClient(ctx, opts, stdin)
	if err != nil {
		return err
	}
	switch args[0] {
	case "list":
		return requestJSON(ctx, client, http.MethodGet, "/api/modules", nil, stdout)
	case "config":
		if len(args) < 3 {
			return errors.New("usage: aegisctl section config <get|apply> <section-id> [json-file] --yes")
		}
		path := "/api/sections/" + args[2] + "/config"
		switch args[1] {
		case "get":
			if len(args) != 3 {
				return errors.New("usage: aegisctl section config get <section-id>")
			}
			return requestJSON(ctx, client, http.MethodGet, path, nil, stdout)
		case "apply":
			if len(args) != 4 {
				return errors.New("usage: aegisctl section config apply <section-id> <json-file> --yes")
			}
			if !opts.yes {
				return errors.New("section configuration apply requires --yes")
			}
			return requestRawFile(ctx, client, http.MethodPut, path, args[3], stdout)
		default:
			return fmt.Errorf("unknown section config command %q", args[1])
		}
	case "test":
		if len(args) != 3 {
			return errors.New("usage: aegisctl section test <section-id> <json-file>")
		}
		return requestRawFile(ctx, client, http.MethodPost, "/api/sections/"+args[1]+"/config/test", args[2], stdout)
	default:
		return fmt.Errorf("unknown section command %q", args[0])
	}
}

func runWAF(ctx context.Context, opts options, args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: aegisctl waf <config|rules|events>")
	}
	client, err := authenticatedClient(ctx, opts, stdin)
	if err != nil {
		return err
	}
	const prefix = "/api/sections/waf_core"
	switch args[0] {
	case "config":
		if len(args) < 2 {
			return errors.New("usage: aegisctl waf config <get|apply|test> [json-file] --yes")
		}
		switch args[1] {
		case "get":
			return requestJSON(ctx, client, http.MethodGet, prefix+"/config", nil, stdout)
		case "apply":
			if len(args) != 3 || !opts.yes {
				return errors.New("usage: aegisctl waf config apply <json-file> --yes")
			}
			return requestRawFile(ctx, client, http.MethodPut, prefix+"/config", args[2], stdout)
		case "test":
			if len(args) != 3 {
				return errors.New("usage: aegisctl waf config test <json-file>")
			}
			return requestRawFile(ctx, client, http.MethodPost, prefix+"/config/test", args[2], stdout)
		default:
			return fmt.Errorf("unknown WAF config command %q", args[1])
		}
	case "rules":
		if len(args) == 1 || args[1] == "list" {
			return requestJSON(ctx, client, http.MethodGet, prefix+"/rules", nil, stdout)
		}
		if args[1] == "validate" && len(args) == 3 {
			return requestRawFile(ctx, client, http.MethodPost, prefix+"/rules/custom/test", args[2], stdout)
		}
		return errors.New("usage: aegisctl waf rules <list|validate <json-file>>")
	case "events":
		return requestJSON(ctx, client, http.MethodGet, prefix+"/events?window=24h&limit=100", nil, stdout)
	default:
		return fmt.Errorf("unknown WAF command %q", args[0])
	}
}

func runEvents(ctx context.Context, opts options, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: aegisctl events <audit|waf>")
	}
	client, err := authenticatedClient(ctx, opts, stdin)
	if err != nil {
		return err
	}
	switch args[0] {
	case "audit":
		if len(args) == 1 || args[1] == "list" {
			return requestJSON(ctx, client, http.MethodGet, "/api/audit-logs?limit=100", nil, stdout)
		}
		if args[1] == "export" {
			data, err := client.Request(ctx, http.MethodGet, "/api/audit-logs/export", nil, "")
			if err != nil {
				return err
			}
			return writeArtifact(stdout, opts, data, "aegis-audit-logs.csv")
		}
	case "waf":
		flags := flag.NewFlagSet("events waf", flag.ContinueOnError)
		flags.SetOutput(stderr)
		window := flags.String("window", "24h", "event time window")
		limit := flags.Int("limit", 100, "maximum number of events (1-1000)")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if *limit < 1 || *limit > 1000 {
			return errors.New("event limit must be between 1 and 1000")
		}
		return requestJSON(ctx, client, http.MethodGet, fmt.Sprintf("/api/sections/waf_core/events?window=%s&limit=%d", *window, *limit), nil, stdout)
	}
	return fmt.Errorf("unknown events command %q", args[0])
}

func runLogs(ctx context.Context, opts options, args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) != 1 || args[0] != "status" {
		return errors.New("usage: aegisctl logs status")
	}
	client, err := authenticatedClient(ctx, opts, stdin)
	if err != nil {
		return err
	}
	return requestJSON(ctx, client, http.MethodGet, "/api/logs", nil, stdout)
}

func runSupportBundle(ctx context.Context, opts options, args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) != 1 || args[0] != "create" {
		return errors.New("usage: aegisctl support-bundle create --output <file>")
	}
	if opts.output == "" {
		return errors.New("support bundle creation requires --output <file>")
	}
	client, err := authenticatedClient(ctx, opts, stdin)
	if err != nil {
		return err
	}
	entries := make(map[string][]byte)
	for name, path := range map[string]string{
		"health.json": "/api/health", "system.json": "/api/system/info", "license.json": "/api/license", "config.yaml": "/api/config/export",
	} {
		data, requestErr := client.Request(ctx, http.MethodGet, path, nil, "")
		if requestErr != nil {
			return fmt.Errorf("collect %s: %w", name, requestErr)
		}
		entries[name] = data
	}
	entries["manifest.json"], _ = json.MarshalIndent(map[string]any{
		"format": "aegis-support-bundle", "version": 1, "created_at": time.Now().UTC(), "sanitized": true,
	}, "", "  ")
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for name, data := range entries {
		file, err := writer.Create(name)
		if err != nil {
			return err
		}
		if _, err := file.Write(data); err != nil {
			return err
		}
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return writeArtifact(stdout, opts, buffer.Bytes(), "aegis-support-bundle.zip")
}

func runUpdate(ctx context.Context, opts options, args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: aegisctl update <check|status|apply|rollback|geo|proxies|all>")
	}
	cfg, err := maintenance.LoadConfig(opts.configPath)
	if err != nil {
		return err
	}
	switch args[0] {
	case "check", "status":
		response, err := maintenance.CallUpdater(ctx, cfg.Updater.SocketPath, maintenance.UpdaterRequest{Operation: "status"})
		if err != nil {
			return err
		}
		return writeJSON(stdout, response)
	case "apply":
		if !opts.yes {
			return errors.New("update apply requires --yes")
		}
		flags := flag.NewFlagSet("update apply", flag.ContinueOnError)
		manifestPath := flags.String("manifest-file", "", "signed artifact manifest file")
		credentialPath := flags.String("credential-file", "", "short-lived artifact credential file")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if *manifestPath == "" {
			return errors.New("update apply requires --manifest-file")
		}
		manifest, err := os.ReadFile(*manifestPath)
		if err != nil {
			return err
		}
		var credential []byte
		if *credentialPath != "" {
			credential, err = os.ReadFile(*credentialPath)
			if err != nil {
				return err
			}
		}
		response, err := maintenance.CallUpdater(ctx, cfg.Updater.SocketPath, maintenance.UpdaterRequest{Operation: "upgrade", Manifest: string(manifest), Credential: string(credential)})
		if err != nil {
			return err
		}
		return writeJSON(stdout, response)
	case "rollback":
		if !opts.yes {
			return errors.New("update rollback requires --yes")
		}
		response, err := maintenance.CallUpdater(ctx, cfg.Updater.SocketPath, maintenance.UpdaterRequest{Operation: "rollback"})
		if err != nil {
			return err
		}
		return writeJSON(stdout, response)
	case "geo":
		if !opts.yes {
			return errors.New("geo update requires --yes")
		}
		if err := maintenance.UpdateGeo(ctx, cfg); err != nil {
			return err
		}
		return writeJSON(stdout, map[string]string{"status": "geo_updated"})
	case "proxies":
		if !opts.yes {
			return errors.New("proxy update requires --yes")
		}
		if err := maintenance.UpdateProxies(ctx, cfg); err != nil {
			return err
		}
		return writeJSON(stdout, map[string]string{"status": "proxies_updated"})
	case "all":
		if !opts.yes {
			return errors.New("update all requires --yes")
		}
		if err := maintenance.UpdateGeo(ctx, cfg); err != nil {
			return err
		}
		if err := maintenance.UpdateProxies(ctx, cfg); err != nil {
			return err
		}
		return writeJSON(stdout, map[string]string{"status": "sources_updated"})
	default:
		return fmt.Errorf("unknown update command %q", args[0])
	}
}

func authenticatedClient(ctx context.Context, opts options, stdin io.Reader) (*operatorcli.Client, error) {
	client, err := operatorcli.NewClient(opts.adminURL, opts.timeout)
	if err != nil {
		return nil, err
	}
	password, err := readCredential(stdin, os.Getenv("AEGISCTL_PASSWORD"), opts.passwordFile, opts.passwordStdin, "administrator password")
	if err != nil {
		return nil, err
	}
	mfaCode, err := readCredential(stdin, os.Getenv("AEGISCTL_MFA_CODE"), opts.mfaFile, opts.mfaStdin, "MFA code")
	if err != nil {
		return nil, err
	}
	if err := client.Authenticate(ctx, operatorcli.Credentials{Username: opts.username, Password: password, MFACode: mfaCode}); err != nil {
		return nil, err
	}
	return client, nil
}

func readCredential(stdin io.Reader, fallback, filePath string, fromStdin bool, label string) (string, error) {
	if filePath != "" && fromStdin {
		return "", fmt.Errorf("%s cannot use both a file and stdin", label)
	}
	if filePath != "" {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(data)), nil
	}
	if fromStdin {
		data, err := io.ReadAll(io.LimitReader(stdin, 1<<20))
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(data)), nil
	}
	return strings.TrimSpace(fallback), nil
}

func readRequiredSecret(stdin io.Reader, envName, fileFlag string, args []string, stdinFlag string) (string, error) {
	filePath := ""
	fromStdin := false
	for index := 0; index < len(args); index++ {
		switch args[index] {
		case fileFlag:
			if index+1 >= len(args) {
				return "", fmt.Errorf("%s requires a path", fileFlag)
			}
			filePath = args[index+1]
		case stdinFlag:
			fromStdin = true
		}
	}
	value, err := readCredential(stdin, os.Getenv(envName), filePath, fromStdin, "new password")
	if err != nil {
		return "", err
	}
	if value == "" {
		return "", fmt.Errorf("new password is required; set %s, use %s <file>, or %s", envName, fileFlag, stdinFlag)
	}
	return value, nil
}

func commandTarget(args []string) (string, []string, error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return "", nil, errors.New("target is required")
	}
	return args[0], args[1:], nil
}

func readKey(args []string, stdin io.Reader, passwordFromStdin bool) (string, error) {
	keyFile := ""
	fromStdin := false
	for index := 0; index < len(args); index++ {
		switch args[index] {
		case "--key-file":
			if index+1 >= len(args) {
				return "", errors.New("--key-file requires a path")
			}
			keyFile = args[index+1]
		case "--key-stdin":
			fromStdin = true
		}
	}
	if keyFile != "" && fromStdin {
		return "", errors.New("licence key cannot use both a file and stdin")
	}
	if fromStdin && passwordFromStdin {
		return "", errors.New("use AEGISCTL_PASSWORD or --password-file when reading the licence key from stdin")
	}
	key, err := readCredential(stdin, os.Getenv("AEGISCTL_LICENSE_KEY"), keyFile, fromStdin, "licence key")
	if err != nil {
		return "", err
	}
	if key == "" {
		return "", errors.New("licence key is required; set AEGISCTL_LICENSE_KEY, use --key-file, or use --key-stdin")
	}
	return key, nil
}

func requestJSON(ctx context.Context, client *operatorcli.Client, method, path string, value any, stdout io.Writer) error {
	data, err := client.JSON(ctx, method, path, value)
	if err != nil {
		return err
	}
	return writeResponse(stdout, data)
}

func requestRawFile(ctx context.Context, client *operatorcli.Client, method, path, filePath string, stdout io.Writer) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	response, err := client.Request(ctx, method, path, bytes.NewReader(data), "application/json")
	if err != nil {
		return err
	}
	return writeResponse(stdout, response)
}

func writeResponse(stdout io.Writer, data []byte) error {
	var value any
	if err := json.Unmarshal(data, &value); err == nil {
		return writeJSON(stdout, value)
	}
	_, err := stdout.Write(data)
	return err
}

func writeJSON(stdout io.Writer, value any) error {
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func writeArtifact(stdout io.Writer, opts options, data []byte, suggestedName string) error {
	if opts.output == "" {
		return fmt.Errorf("this command produces %s; provide --output <file>", suggestedName)
	}
	flags := os.O_WRONLY | os.O_CREATE
	if opts.force {
		flags |= os.O_TRUNC
	} else {
		flags |= os.O_EXCL
	}
	file, err := os.OpenFile(filepath.Clean(opts.output), flags, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	return writeJSON(stdout, map[string]any{"status": "written", "path": opts.output, "bytes": len(data)})
}

func usage(w io.Writer) {
	fmt.Fprint(w, `Aegis operator CLI

Usage:
  aegisctl [global flags] <command> [arguments]

Commands:
  status | health | version | doctor
  user list|reset-password|enable|disable|revoke-sessions
  mfa reset <username>
  license status|activate|refresh|deactivate
  config validate|show|export|backup create|apply|restore|reset
  backup create|restore
  system factory-reset
  tls status|list|config|upload|delete
  section list|config|get|test
  waf config|rules|events
  events audit|waf
  logs status
  support-bundle create
  update check|status|apply|rollback|geo|proxies|all

Use --yes for destructive actions and --confirm RESET-CONFIG for a bootstrap
configuration reset. Factory reset preserves the control plane, licences,
certificates, and event data by design.
`)
}
