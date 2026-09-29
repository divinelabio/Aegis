package maintenance

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/oschwald/geoip2-golang"
)

const (
	maxGeoCompressed = 32 << 20
	maxGeoExpanded   = 64 << 20
)

func UpdateGeo(ctx context.Context, cfg Config) error {
	destination := cfg.Sections.TrafficControl.Geo.DBPath
	return withLock(destination, func() error {
		source := "https://download.db-ip.com/free/dbip-country-lite-" + time.Now().UTC().Format("2006-01") + ".mmdb.gz"
		data, err := downloadGeo(ctx, source, "download.db-ip.com", maxGeoCompressed)
		if err != nil {
			return err
		}
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return fmt.Errorf("invalid gzip payload: %w", err)
		}
		decompressed, err := io.ReadAll(io.LimitReader(gz, maxGeoExpanded+1))
		_ = gz.Close()
		if err != nil {
			return err
		}
		if len(decompressed) > maxGeoExpanded {
			return fmt.Errorf("expanded mmdb exceeds %d bytes", maxGeoExpanded)
		}
		reader, err := geoip2.FromBytes(decompressed)
		if err != nil {
			return fmt.Errorf("downloaded mmdb is invalid: %w", err)
		}
		dbType := strings.ToLower(reader.Metadata().DatabaseType)
		if !strings.Contains(dbType, "country") && !strings.Contains(dbType, "city") && !strings.Contains(dbType, "location") {
			return fmt.Errorf("downloaded mmdb has unsupported type %q", reader.Metadata().DatabaseType)
		}
		if _, err := reader.Country(net.ParseIP("8.8.8.8")); err != nil {
			return fmt.Errorf("downloaded mmdb test lookup failed: %w", err)
		}
		manifest, err := publish(destination, decompressed, source)
		if err == nil {
			fmt.Printf("GeoIP database published: %s (%s)\n", destination, manifest.Generation)
		}
		return err
	})
}

func downloadGeo(ctx context.Context, rawURL, requiredHost string, maxBytes int64) ([]byte, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() != requiredHost || parsed.User != nil {
		return nil, fmt.Errorf("unsafe update URL %q", rawURL)
	}
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 || req.URL.Scheme != "https" || req.URL.Hostname() != requiredHost {
			return fmt.Errorf("unsafe redirect")
		}
		return nil
	}}
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
		return nil, fmt.Errorf("download returned HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > maxBytes {
		return nil, fmt.Errorf("download exceeds %d bytes", maxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if len(data) > int(maxBytes) {
		return nil, fmt.Errorf("download exceeds %d bytes", maxBytes)
	}
	return data, err
}
