package config

import (
	"errors"
	"net/mail"
	"net/url"
	"strings"
)

// SecurityTXTConfig controls the public RFC 9116 disclosure contact.
type SecurityTXTConfig struct {
	Contact string `mapstructure:"contact" json:"contact"`
}

// NormalizeSecurityTXTContact validates a configured contact and returns the
// value used in the public Contact field. Plain email addresses are converted
// to mailto URIs.
func NormalizeSecurityTXTContact(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	if len(value) > 2048 || strings.ContainsAny(value, "\r\n\x00") {
		return "", errors.New("contact contains invalid characters")
	}
	if !strings.Contains(value, ":") {
		address, err := mail.ParseAddress(value)
		if err != nil || address.Address != value {
			return "", errors.New("contact must be an email address, mailto URI, or HTTPS URL")
		}
		return "mailto:" + address.Address, nil
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Fragment != "" {
		return "", errors.New("contact is not a valid URI")
	}
	switch strings.ToLower(parsed.Scheme) {
	case "mailto":
		address, err := mail.ParseAddress(strings.TrimPrefix(value, parsed.Scheme+":"))
		if err != nil || address.Address == "" {
			return "", errors.New("mailto contact is invalid")
		}
		return "mailto:" + address.Address, nil
	case "https":
		if parsed.Hostname() == "" || parsed.User != nil {
			return "", errors.New("HTTPS contact must include a host and no credentials")
		}
		return parsed.String(), nil
	default:
		return "", errors.New("contact URI must use mailto or HTTPS")
	}
}
