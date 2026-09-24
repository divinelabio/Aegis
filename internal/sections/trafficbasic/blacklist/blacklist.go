// Package blacklist provides IP and CIDR blocklist functionality
package blacklist

import (
	"net"
	"sync"
	"time"

	"github.com/yl2chen/cidranger"
)

// Blacklist manages blocked IPs and CIDRs
type Blacklist struct {
	mu         sync.RWMutex
	ips        map[string]*BlockEntry // Exact IP matches (O(1))
	cidrs      []*CIDREntry           // CIDR entries for metadata
	cidrRanger cidranger.Ranger       // Trie for O(k) CIDR lookup
	enabled    bool
}

// BlockEntry represents a blocked IP
type BlockEntry struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at,omitempty"` // Zero means never expires
}

// CIDREntry represents a blocked CIDR range
type CIDREntry struct {
	CIDR      string     `json:"cidr"`
	Network   *net.IPNet `json:"-"`
	Reason    string     `json:"reason"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at,omitempty"`
}

// rangerEntry wraps CIDREntry for cidranger
type rangerEntry struct {
	network net.IPNet
	entry   *CIDREntry
}

func (e *rangerEntry) Network() net.IPNet { return e.network }

// New creates a new Blacklist
func New() *Blacklist {
	return &Blacklist{
		ips:        make(map[string]*BlockEntry),
		cidrs:      make([]*CIDREntry, 0),
		cidrRanger: cidranger.NewPCTrieRanger(),
		enabled:    true,
	}
}

// SetEnabled enables or disables the blacklist
func (b *Blacklist) SetEnabled(enabled bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.enabled = enabled
}

// IsEnabled returns whether the blacklist is enabled
func (b *Blacklist) IsEnabled() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.enabled
}

// IsBlocked checks if an IP is blocked
func (b *Blacklist) IsBlocked(ip string) (bool, string) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if !b.enabled {
		return false, ""
	}

	// Check exact IP match first (O(1))
	if entry, exists := b.ips[ip]; exists {
		// Check expiration
		if !entry.ExpiresAt.IsZero() && time.Now().After(entry.ExpiresAt) {
			// Expired - will be cleaned up later
			return false, ""
		}
		return true, entry.Reason
	}

	// Check CIDR ranges using trie (O(k) where k = IP bits)
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false, ""
	}

	// Use cidranger for fast O(k) lookup
	entries, err := b.cidrRanger.ContainingNetworks(parsedIP)
	if err != nil || len(entries) == 0 {
		return false, ""
	}

	// Check first matching entry for expiration
	now := time.Now()
	for _, e := range entries {
		if re, ok := e.(*rangerEntry); ok {
			if !re.entry.ExpiresAt.IsZero() && now.After(re.entry.ExpiresAt) {
				continue // Expired
			}
			return true, re.entry.Reason
		}
	}

	return false, ""
}

// AddIP adds an IP to the blacklist
func (b *Blacklist) AddIP(ip string, reason string, duration time.Duration) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	entry := &BlockEntry{
		IP:        ip,
		Reason:    reason,
		CreatedAt: time.Now(),
	}

	if duration > 0 {
		entry.ExpiresAt = time.Now().Add(duration)
	}

	b.ips[ip] = entry
	return nil
}

// AddCIDR adds a CIDR range to the blacklist
func (b *Blacklist) AddCIDR(cidr string, reason string, duration time.Duration) error {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	entry := &CIDREntry{
		CIDR:      cidr,
		Network:   network,
		Reason:    reason,
		CreatedAt: time.Now(),
	}

	if duration > 0 {
		entry.ExpiresAt = time.Now().Add(duration)
	}

	// Add to both slice (for listing) and trie (for fast lookup)
	b.cidrs = append(b.cidrs, entry)
	b.cidrRanger.Insert(&rangerEntry{network: *network, entry: entry})
	return nil
}

// RemoveIP removes an IP from the blacklist
func (b *Blacklist) RemoveIP(ip string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, exists := b.ips[ip]; exists {
		delete(b.ips, ip)
		return true
	}
	return false
}

// RemoveCIDR removes a CIDR from the blacklist
func (b *Blacklist) RemoveCIDR(cidr string) bool {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	for i, entry := range b.cidrs {
		if entry.CIDR == cidr {
			b.cidrs = append(b.cidrs[:i], b.cidrs[i+1:]...)
			// Also remove from trie
			b.cidrRanger.Remove(*network)
			return true
		}
	}
	return false
}

// LoadIPs loads multiple IPs into the blacklist
func (b *Blacklist) LoadIPs(ips []string, reason string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for _, ip := range ips {
		b.ips[ip] = &BlockEntry{
			IP:        ip,
			Reason:    reason,
			CreatedAt: time.Now(),
		}
	}
}

// LoadCIDRs loads multiple CIDRs into the blacklist
func (b *Blacklist) LoadCIDRs(cidrs []string, reason string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue // Skip invalid CIDRs
		}
		entry := &CIDREntry{
			CIDR:      cidr,
			Network:   network,
			Reason:    reason,
			CreatedAt: time.Now(),
		}
		b.cidrs = append(b.cidrs, entry)
		// Also insert into trie for fast lookup
		b.cidrRanger.Insert(&rangerEntry{network: *network, entry: entry})
	}
	return nil
}

// CleanExpired removes expired entries
func (b *Blacklist) CleanExpired() int {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	count := 0

	// Clean expired IPs
	for ip, entry := range b.ips {
		if !entry.ExpiresAt.IsZero() && now.After(entry.ExpiresAt) {
			delete(b.ips, ip)
			count++
		}
	}

	// Clean expired CIDRs - remove from both slice AND trie
	newCIDRs := make([]*CIDREntry, 0, len(b.cidrs))
	for _, cidr := range b.cidrs {
		if cidr.ExpiresAt.IsZero() || now.Before(cidr.ExpiresAt) {
			newCIDRs = append(newCIDRs, cidr)
		} else {
			// CRITICAL: Also remove from trie to maintain consistency
			if cidr.Network != nil {
				b.cidrRanger.Remove(*cidr.Network)
			}
			count++
		}
	}
	b.cidrs = newCIDRs

	return count
}

// Count returns the number of blocked IPs and CIDRs
func (b *Blacklist) Count() (ips int, cidrs int) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.ips), len(b.cidrs)
}

// ListIPs returns all blocked IPs
func (b *Blacklist) ListIPs() []*BlockEntry {
	b.mu.RLock()
	defer b.mu.RUnlock()

	result := make([]*BlockEntry, 0, len(b.ips))
	for _, entry := range b.ips {
		result = append(result, entry)
	}
	return result
}

// ListCIDRs returns all blocked CIDRs
func (b *Blacklist) ListCIDRs() []*CIDREntry {
	b.mu.RLock()
	defer b.mu.RUnlock()

	result := make([]*CIDREntry, len(b.cidrs))
	copy(result, b.cidrs)
	return result
}
