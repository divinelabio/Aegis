package maintenance

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const maxProxyList = 5 << 20

func UpdateProxies(ctx context.Context, cfg Config) error {
	tp := cfg.Infrastructure.TrustedProxies
	return withLock(tp.CombinedList, func() error {
		entries := make(map[string]struct{})
		for _, value := range tp.CIDRs {
			if normalized, ok := normalizeNetwork(value); ok {
				entries[normalized] = struct{}{}
			} else {
				return fmt.Errorf("invalid configured trusted proxy %q", value)
			}
		}
		cacheDir := filepath.Join(filepath.Dir(tp.CombinedList), "cache")
		if err := os.MkdirAll(cacheDir, 0755); err != nil {
			return err
		}
		for _, rawURL := range tp.SourceURLs {
			data, err := fetchProxySource(ctx, rawURL)
			cachePath := filepath.Join(cacheDir, sourceID(rawURL)+".list")
			if err != nil {
				data, err = os.ReadFile(cachePath)
				if err != nil {
					return fmt.Errorf("trusted proxy source %s failed without cache: %w", rawURL, err)
				}
				fmt.Printf("Trusted proxy source unavailable; using cache: %s\n", rawURL)
			} else if err := os.WriteFile(cachePath, data, 0644); err != nil {
				return err
			}
			if err := addProxyEntries(entries, data); err != nil {
				return fmt.Errorf("trusted proxy source %s: %w", rawURL, err)
			}
		}
		for _, name := range tp.SourceFiles {
			path, err := controlledSourcePath(tp.SourceRoot, name)
			if err != nil {
				return err
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if len(data) > maxProxyList {
				return fmt.Errorf("trusted proxy file %s exceeds %d bytes", path, maxProxyList)
			}
			if err := addProxyEntries(entries, data); err != nil {
				return fmt.Errorf("trusted proxy file %s: %w", path, err)
			}
		}
		values := make([]string, 0, len(entries))
		for value := range entries {
			values = append(values, value)
		}
		sort.Strings(values)
		data := []byte(strings.Join(values, "\n") + "\n")
		manifest, err := publish(tp.CombinedList, data, "trusted-proxy-sources")
		if err == nil {
			fmt.Printf("Trusted proxy list published: %s (%s, %d entries)\n", tp.CombinedList, manifest.Generation, len(values))
		}
		return err
	})
}

func fetchProxySource(ctx context.Context, rawURL string) ([]byte, error) {
	parsed, addresses, err := resolveProxyURL(rawURL)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil || !strings.EqualFold(host, parsed.Hostname()) {
			return nil, fmt.Errorf("trusted proxy source attempted an unvalidated connection to %q", address)
		}
		var lastErr error
		for _, ip := range addresses {
			conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if dialErr == nil {
				return conn, nil
			}
			lastErr = dialErr
		}
		return nil, lastErr
	}
	client := &http.Client{
		Timeout: 20 * time.Second, Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			if req.URL.Scheme != "https" || !strings.EqualFold(req.URL.Hostname(), parsed.Hostname()) || req.URL.User != nil {
				return fmt.Errorf("redirect left the validated HTTPS origin")
			}
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > maxProxyList {
		return nil, fmt.Errorf("source exceeds %d bytes", maxProxyList)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxProxyList+1))
	if len(data) > maxProxyList {
		return nil, fmt.Errorf("source exceeds %d bytes", maxProxyList)
	}
	return data, err
}

func resolveProxyURL(rawURL string) (*url.URL, []net.IP, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil {
		return nil, nil, fmt.Errorf("trusted proxy source must be an HTTPS URL without inline credentials")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupIP(ctx, "ip", parsed.Hostname())
	if err != nil {
		return nil, nil, err
	}
	if len(addresses) == 0 {
		return nil, nil, fmt.Errorf("trusted proxy source host has no IP addresses")
	}
	for _, ip := range addresses {
		if !isPublicIP(ip) {
			return nil, nil, fmt.Errorf("trusted proxy source resolves to non-public address %s", ip)
		}
	}
	return parsed, addresses, nil
}

func isPublicIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		return v4[0] != 0 && v4[0] != 127 && !(v4[0] == 169 && v4[1] == 254)
	}
	return true
}

func controlledSourcePath(root, name string) (string, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	path := name
	if !filepath.IsAbs(path) {
		path = filepath.Join(root, path)
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("trusted proxy file %q escapes source root", name)
	}
	return path, nil
}

func addProxyEntries(entries map[string]struct{}, data []byte) error {
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if idx := strings.IndexAny(line, "#;"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		normalized, ok := normalizeNetwork(line)
		if !ok {
			return fmt.Errorf("invalid IP or CIDR %q", line)
		}
		entries[normalized] = struct{}{}
		if len(entries) > 100000 {
			return fmt.Errorf("combined trusted proxy list exceeds 100000 entries")
		}
	}
	return scanner.Err()
}

func normalizeNetwork(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if ip := net.ParseIP(value); ip != nil {
		return ip.String(), true
	}
	_, network, err := net.ParseCIDR(value)
	if err != nil {
		return "", false
	}
	return network.String(), true
}

func sourceID(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
