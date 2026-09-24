package telemetry

import (
	"fmt"
	"net"

	"github.com/oschwald/geoip2-golang"
)

// MMDBLookup implements GeoLookup using standard MMDB format
type MMDBLookup struct {
	reader *geoip2.Reader
}

// NewMMDBLookup creates a new lookup from a DB file
func NewMMDBLookup(dbPath string) (*MMDBLookup, error) {
	db, err := geoip2.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open mmdb: %w", err)
	}

	return &MMDBLookup{
		reader: db,
	}, nil
}

// LookupCountry returns the ISO country code (e.g., "US", "CN")
func (m *MMDBLookup) LookupCountry(ip string) (string, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return "", fmt.Errorf("invalid ip: %s", ip)
	}

	record, err := m.reader.Country(parsedIP)
	if err != nil {
		return "", err
	}

	return record.Country.IsoCode, nil
}

// Close closes the database connection
func (m *MMDBLookup) Close() error {
	if m.reader != nil {
		return m.reader.Close()
	}
	return nil
}
