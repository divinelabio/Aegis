package telemetry

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/divinelab-io/aegis/internal/analytics"
	"github.com/divinelab-io/aegis/internal/infra/config"
	"github.com/divinelab-io/aegis/internal/infra/metrics"
	"github.com/divinelab-io/aegis/internal/infra/requestctx"
	"github.com/divinelab-io/aegis/internal/infra/storage"
)

type key int

const RequestIDKey key = 0

var (
	// UnifiedMetrics is the global unified metrics collector (set during initialization)
	UnifiedMetrics *metrics.UnifiedCollector
	AnalyticsStore *analytics.Store
)

// SetUnifiedMetrics sets the global unified metrics collector
func SetUnifiedMetrics(collector *metrics.UnifiedCollector) {
	UnifiedMetrics = collector
}

func SetAnalyticsStore(store *analytics.Store) {
	AnalyticsStore = store
}

// Middleware adds request logging, ID tracking, and metrics collection.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		var duration float64
		reqID := uuid.New().String()

		// Inject Request ID into Context and Response Headers
		ctx := context.WithValue(r.Context(), RequestIDKey, reqID)
		r = r.WithContext(ctx)
		r = WithRequestLogMetadata(r)
		w.Header().Set("X-Request-ID", reqID)

		// Wrap ResponseWriter to capture status code and bytes
		wrapped := &responseWrapper{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
			bytesWritten:   0,
		}

		next.ServeHTTP(wrapped, r)
		elapsed := time.Since(start)
		duration = elapsed.Seconds()
		latencyMs := duration * 1000

		// Record to UNIFIED METRICS (new system)
		if UnifiedMetrics != nil {
			identity, _ := requestctx.FromRequest(r)
			clientIP := identity.ClientIP
			country := identity.Geo.Country

			UnifiedMetrics.RecordHTTPRequest(metrics.HTTPRequestMetric{
				Timestamp:  start,
				Method:     r.Method,
				Path:       r.URL.Path,
				StatusCode: wrapped.statusCode,
				LatencyMs:  latencyMs,
				ClientIP:   clientIP,
				UserAgent:  r.UserAgent(),
				Referrer:   r.Referer(),
				Country:    country,
				BytesSent:  int64(wrapped.bytesWritten),
				BytesRecv:  r.ContentLength,
			})
		}

		detailedRequestLogging := true
		if cfg := config.GetGlobalConfig(); cfg != nil {
			detailedRequestLogging = cfg.Telemetry.RequestLogging
		}

		// Record to OLD TELEMETRY SYSTEM (for backward compatibility during transition)
		RecordStatus(wrapped.statusCode)
		RecordLatency(int64(latencyMs))
		RequestLatency.WithLabelValues(r.URL.Path).Observe(duration)

		identity, _ := requestctx.FromRequest(r)
		clientIP := identity.ClientIP
		country := identity.Geo.Country
		if detailedRequestLogging {
			metadata := RequestLogMetadataFromRequest(r)
			host := metadata.Host
			if host == "" {
				host = r.Host
			}
			// Record Detailed Analytics (old system)
			RecordRequest(
				clientIP,
				r.URL.Path,
				r.UserAgent(),
				country,
				r.Referer(),
			)

			// Async Log to DB
			storage.LogRequest(storage.RequestLog{
				Timestamp:           time.Now().Unix(),
				IP:                  clientIP,
				Host:                host,
				Path:                r.URL.Path,
				Method:              r.Method,
				Status:              wrapped.statusCode,
				LatencyMs:           int64(latencyMs),
				UserAgent:           r.UserAgent(),
				Referer:             r.Referer(),
				Country:             country,
				Blocked:             wrapped.statusCode == 403,
				RuleID:              metadata.RuleID,
				RuleName:            metadata.RuleName,
				RuleType:            metadata.RuleType,
				RequestID:           reqID,
				Upstream:            metadata.Upstream,
				RouteName:           metadata.RouteName,
				BytesSent:           int64(wrapped.bytesWritten),
				ASN:                 r.Header.Get("X-Aegis-ASN"),
				ASNOrg:              r.Header.Get("X-Aegis-ASN-Org"),
				JA3:                 r.Header.Get("X-Aegis-TLS-JA3"),
				JA4:                 r.Header.Get("X-Aegis-TLS-JA4"),
				HTTPVersion:         requestHTTPVersion(r),
				TLSVersion:          requestTLSVersion(r),
				IPVersion:           clientIPVersion(clientIP),
				ResponseContentType: responseContentType(wrapped),
			})
		}
		WriteAccessLog(AccessLogEntry{
			Timestamp: start,
			ClientIP:  clientIP,
			Method:    r.Method,
			Path:      RedactRequestURI(r.URL),
			Protocol:  r.Proto,
			Status:    wrapped.statusCode,
			BytesSent: wrapped.bytesWritten,
			Referer:   r.Referer(),
			UserAgent: r.UserAgent(),
			RequestID: reqID,
			Latency:   elapsed,
		})
		// Simple Console Logging
		if Logger != nil {
			Logger.Info("Request",
				zap.String("req_id", reqID),
				zap.String("method", r.Method),
				zap.String("path", r.URL.Path),
				zap.Int("status", wrapped.statusCode),
				zap.Float64("duration", duration),
				zap.String("ip", clientIP),
			)
		}
	})
}

func requestHTTPVersion(r *http.Request) string {
	if r == nil {
		return ""
	}
	switch r.ProtoMajor {
	case 1:
		if r.ProtoMinor == 0 {
			return "HTTP/1.0"
		}
		return "HTTP/1.1"
	case 2:
		return "HTTP/2"
	case 3:
		return "HTTP/3"
	default:
		return strings.TrimSpace(r.Proto)
	}
}

func requestTLSVersion(r *http.Request) string {
	if r == nil {
		return ""
	}
	if value := strings.TrimSpace(r.Header.Get("X-Aegis-TLS-Version")); value != "" {
		return value
	}
	if r.TLS == nil {
		return ""
	}
	switch r.TLS.Version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return ""
	}
}

func clientIPVersion(clientIP string) string {
	ip := net.ParseIP(strings.TrimSpace(clientIP))
	if ip == nil {
		return ""
	}
	if ip.To4() != nil {
		return "IPv4"
	}
	return "IPv6"
}

func responseContentType(w http.ResponseWriter) string {
	if w == nil {
		return ""
	}
	value := strings.SplitN(w.Header().Get("Content-Type"), ";", 2)[0]
	return strings.ToLower(strings.TrimSpace(value))
}

// responseWrapper captures status code and bytes written
type responseWrapper struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int
}

func (rw *responseWrapper) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWrapper) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.bytesWritten += n
	return n, err
}
