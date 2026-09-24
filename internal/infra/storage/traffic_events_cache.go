package storage

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	trafficEventsDashboardCacheTTL        = 35 * time.Second
	trafficEventsDashboardCacheMaxEntries = 64
)

type trafficEventsDashboardCacheEntry struct {
	dashboard TrafficEventsDashboard
	expiresAt time.Time
}

type trafficEventsDashboardCall struct {
	done      chan struct{}
	dashboard TrafficEventsDashboard
	err       error
}

// trafficEventsDashboardCache makes the unfiltered dashboard read-through and
// coalesces concurrent refreshes. Filtered or paginated views remain live so
// operators never receive a cached search result.
type trafficEventsDashboardCache struct {
	mu       sync.Mutex
	entries  map[string]trafficEventsDashboardCacheEntry
	inflight map[string]*trafficEventsDashboardCall
}

var defaultTrafficEventsDashboardCache trafficEventsDashboardCache

func GetCachedTrafficEventsDashboard(q TrafficEventsQuery) (TrafficEventsDashboard, error) {
	return GetCachedTrafficEventsDashboardContext(context.Background(), q)
}

func GetCachedTrafficEventsDashboardContext(ctx context.Context, q TrafficEventsQuery) (TrafficEventsDashboard, error) {
	return defaultTrafficEventsDashboardCache.get(ctx, q, GetTrafficEventsDashboardContext)
}

func (c *trafficEventsDashboardCache) get(ctx context.Context, q TrafficEventsQuery, load func(context.Context, TrafficEventsQuery) (TrafficEventsDashboard, error)) (TrafficEventsDashboard, error) {
	if err := ctx.Err(); err != nil {
		return TrafficEventsDashboard{}, err
	}
	if !cacheableTrafficEventsDashboardQuery(q) {
		return load(ctx, q)
	}

	key := trafficEventsDashboardCacheKey(q)
	now := time.Now()
	c.mu.Lock()
	if entry, ok := c.entries[key]; ok && now.Before(entry.expiresAt) {
		dashboard := cloneTrafficEventsDashboard(entry.dashboard)
		c.mu.Unlock()
		return dashboard, nil
	}
	if call, ok := c.inflight[key]; ok {
		c.mu.Unlock()
		select {
		case <-call.done:
			return cloneTrafficEventsDashboard(call.dashboard), call.err
		case <-ctx.Done():
			return TrafficEventsDashboard{}, ctx.Err()
		}
	}
	if c.entries == nil {
		c.entries = make(map[string]trafficEventsDashboardCacheEntry)
	}
	if c.inflight == nil {
		c.inflight = make(map[string]*trafficEventsDashboardCall)
	}
	call := &trafficEventsDashboardCall{done: make(chan struct{})}
	c.inflight[key] = call
	c.mu.Unlock()

	dashboard, err := load(ctx, q)

	c.mu.Lock()
	call.dashboard = cloneTrafficEventsDashboard(dashboard)
	call.err = err
	delete(c.inflight, key)
	if err == nil {
		c.evictOneEntryIfFull()
		c.entries[key] = trafficEventsDashboardCacheEntry{
			dashboard: cloneTrafficEventsDashboard(dashboard),
			expiresAt: time.Now().Add(trafficEventsDashboardCacheTTL),
		}
	}
	close(call.done)
	c.mu.Unlock()
	return dashboard, err
}

func cacheableTrafficEventsDashboardQuery(q TrafficEventsQuery) bool {
	return q.Status == "" && q.StatusClass == "" && q.IP == "" && q.Country == "" &&
		q.Method == "" && q.Host == "" && q.Path == "" && q.UserAgent == "" &&
		q.JA3 == "" && q.JA4 == "" && q.ASN == "" && q.Route == "" && q.Upstream == "" &&
		q.HTTPVersion == "" && q.TLSVersion == "" && q.IPVersion == "" && q.ContentType == "" &&
		q.RequestID == "" && q.Since == "" && q.Until == "" && q.Cursor == ""
}

func trafficEventsDashboardCacheKey(q TrafficEventsQuery) string {
	sort := "desc"
	if strings.EqualFold(strings.TrimSpace(q.Sort), "asc") {
		sort = "asc"
	}
	return strings.Join([]string{
		strings.ToLower(strings.TrimSpace(q.Window)),
		strings.ToLower(strings.TrimSpace(q.Interval)),
		strconv.Itoa(q.Limit),
		sort,
	}, "\x00")
}

func (c *trafficEventsDashboardCache) evictOneEntryIfFull() {
	if len(c.entries) < trafficEventsDashboardCacheMaxEntries {
		return
	}
	now := time.Now()
	for key, entry := range c.entries {
		if !now.Before(entry.expiresAt) {
			delete(c.entries, key)
			return
		}
	}
	for key := range c.entries {
		delete(c.entries, key)
		return
	}
}

func cloneTrafficEventsDashboard(source TrafficEventsDashboard) TrafficEventsDashboard {
	cloned := source
	cloned.Timeseries = make([]TrafficEventsTimeseriesPoint, len(source.Timeseries))
	for index, point := range source.Timeseries {
		cloned.Timeseries[index] = point
		if point.Counts != nil {
			cloned.Timeseries[index].Counts = make(map[string]int64, len(point.Counts))
			for key, count := range point.Counts {
				cloned.Timeseries[index].Counts[key] = count
			}
		}
	}
	cloned.Breakdowns = make(map[string][]TrafficEventsBreakdownItem, len(source.Breakdowns))
	for dimension, items := range source.Breakdowns {
		cloned.Breakdowns[dimension] = append([]TrafficEventsBreakdownItem(nil), items...)
	}
	cloned.Map = append([]TrafficEventsMapItem(nil), source.Map...)
	cloned.Events = source.Events
	cloned.Events.Events = make([]TrafficEventsEvent, len(source.Events.Events))
	for index, event := range source.Events.Events {
		cloned.Events.Events[index] = event
		if event.Metadata != nil {
			cloned.Events.Events[index].Metadata = make(map[string]string, len(event.Metadata))
			for key, value := range event.Metadata {
				cloned.Events.Events[index].Metadata[key] = value
			}
		}
	}
	cloned.Warnings = append([]string(nil), source.Warnings...)
	return cloned
}
