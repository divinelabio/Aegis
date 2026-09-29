package transport

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
)

const maxDeliveryCompressionBuffer = 8 << 20

type DeliveryCompressionConfig struct {
	Enabled      bool
	MinSize      int
	ContentTypes []string
	Level        int
}

type DeliveryCompressionProvider func() DeliveryCompressionConfig

func DeliveryCompressionMiddleware(provider DeliveryCompressionProvider) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			config := DeliveryCompressionConfig{}
			if provider != nil {
				config = provider()
			}
			if !config.Enabled || requestBypassesDeliveryCompression(r) {
				next.ServeHTTP(w, r)
				return
			}
			writer := newDeliveryResponseWriter(w)
			next.ServeHTTP(writer, r)
			writer.finish(r, config)
		})
	}
}

type deliveryResponseWriter struct {
	underlying  http.ResponseWriter
	header      http.Header
	body        bytes.Buffer
	status      int
	passthrough bool
	committed   bool
}

func newDeliveryResponseWriter(underlying http.ResponseWriter) *deliveryResponseWriter {
	return &deliveryResponseWriter{underlying: underlying, header: cloneHTTPHeader(underlying.Header())}
}

func (w *deliveryResponseWriter) Header() http.Header {
	if w.passthrough {
		return w.underlying.Header()
	}
	return w.header
}

func (w *deliveryResponseWriter) WriteHeader(status int) {
	if w.passthrough {
		w.underlying.WriteHeader(status)
		return
	}
	if w.status == 0 {
		w.status = status
	}
}

func (w *deliveryResponseWriter) Write(body []byte) (int, error) {
	if w.passthrough {
		return w.underlying.Write(body)
	}
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if isStreamingContentType(w.header.Get("Content-Type")) || w.body.Len()+len(body) > maxDeliveryCompressionBuffer {
		w.commitRaw()
		return w.underlying.Write(body)
	}
	return w.body.Write(body)
}

func (w *deliveryResponseWriter) Flush() {
	w.commitRaw()
	if flusher, ok := w.underlying.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *deliveryResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.underlying.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("underlying response writer does not support hijacking")
	}
	if w.status != 0 || w.body.Len() > 0 {
		w.commitRaw()
	} else {
		replaceHTTPHeader(w.underlying.Header(), w.header)
		w.committed = true
		w.passthrough = true
	}
	return hijacker.Hijack()
}

func (w *deliveryResponseWriter) Push(target string, options *http.PushOptions) error {
	if pusher, ok := w.underlying.(http.Pusher); ok {
		return pusher.Push(target, options)
	}
	return http.ErrNotSupported
}

func (w *deliveryResponseWriter) Unwrap() http.ResponseWriter { return w.underlying }

func (w *deliveryResponseWriter) finish(r *http.Request, config DeliveryCompressionConfig) {
	if w.committed || w.passthrough {
		return
	}
	status := w.status
	if status == 0 {
		status = http.StatusOK
	}
	body := w.body.Bytes()
	compress := acceptsGzip(r.Header.Get("Accept-Encoding")) && responseCanHaveBody(r.Method, status) &&
		w.header.Get("Content-Encoding") == "" && w.header.Get("Content-Range") == "" &&
		len(body) >= maxInt(config.MinSize, 0) && deliveryContentTypeAllowed(w.header.Get("Content-Type"), body, config.ContentTypes)
	if compress {
		var compressed bytes.Buffer
		level := config.Level
		if level < gzip.HuffmanOnly || level > gzip.BestCompression {
			level = gzip.DefaultCompression
		}
		writer, err := gzip.NewWriterLevel(&compressed, level)
		if err == nil {
			_, writeErr := writer.Write(body)
			closeErr := writer.Close()
			if writeErr == nil && closeErr == nil {
				body = compressed.Bytes()
				w.header.Set("Content-Encoding", "gzip")
				appendHeaderToken(w.header, "Vary", "Accept-Encoding")
			}
		}
	}
	w.writeFinal(status, body)
}

func (w *deliveryResponseWriter) commitRaw() {
	if w.committed {
		return
	}
	status := w.status
	if status == 0 {
		status = http.StatusOK
	}
	// A flush switches the writer to streaming mode, so the final response
	// length is not yet known and must not be synthesized here.
	w.header.Del("Content-Length")
	replaceHTTPHeader(w.underlying.Header(), w.header)
	w.underlying.WriteHeader(status)
	if w.body.Len() > 0 {
		_, _ = w.underlying.Write(w.body.Bytes())
	}
	w.committed = true
	w.passthrough = true
}

func (w *deliveryResponseWriter) writeFinal(status int, body []byte) {
	if w.committed {
		return
	}
	w.committed = true
	w.header.Del("Content-Length")
	if responseCanHaveBody(http.MethodGet, status) {
		w.header.Set("Content-Length", strconv.Itoa(len(body)))
	}
	replaceHTTPHeader(w.underlying.Header(), w.header)
	w.underlying.WriteHeader(status)
	if len(body) > 0 {
		_, _ = w.underlying.Write(body)
	}
}

func requestBypassesDeliveryCompression(r *http.Request) bool {
	if r == nil || r.Method == http.MethodHead || r.Header.Get("Range") != "" {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket") || headerHasToken(r.Header, "Connection", "upgrade")
}

func isStreamingContentType(value string) bool {
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(value, ";")[0]))
	return mediaType == "text/event-stream" || mediaType == "application/x-ndjson"
}

func acceptsGzip(value string) bool {
	var gzipQuality, wildcardQuality *float64
	for _, entry := range strings.Split(value, ",") {
		parts := strings.Split(strings.TrimSpace(entry), ";")
		encoding := strings.TrimSpace(parts[0])
		if !strings.EqualFold(encoding, "gzip") && encoding != "*" {
			continue
		}
		quality := 1.0
		for _, parameter := range parts[1:] {
			keyValue := strings.SplitN(strings.TrimSpace(parameter), "=", 2)
			if len(keyValue) == 2 && strings.EqualFold(keyValue[0], "q") {
				if parsed, err := strconv.ParseFloat(keyValue[1], 64); err == nil && parsed >= 0 && parsed <= 1 {
					quality = parsed
				} else {
					quality = 0
				}
			}
		}
		if strings.EqualFold(encoding, "gzip") {
			gzipQuality = &quality
		} else {
			wildcardQuality = &quality
		}
	}
	if gzipQuality != nil {
		return *gzipQuality > 0
	}
	if wildcardQuality != nil {
		return *wildcardQuality > 0
	}
	return false
}

func deliveryContentTypeAllowed(contentType string, body []byte, allowed []string) bool {
	if contentType == "" && len(body) > 0 {
		contentType = http.DetectContentType(body)
	}
	contentType = strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	for _, candidate := range allowed {
		candidate = strings.ToLower(strings.TrimSpace(candidate))
		if candidate != "" && (contentType == candidate || strings.HasPrefix(contentType, candidate)) {
			return true
		}
	}
	return false
}

func responseCanHaveBody(method string, status int) bool {
	return method != http.MethodHead && status >= 200 && status != http.StatusNoContent && status != http.StatusNotModified
}

func appendHeaderToken(header http.Header, name, value string) {
	for _, existing := range header.Values(name) {
		for _, token := range strings.Split(existing, ",") {
			if strings.EqualFold(strings.TrimSpace(token), value) {
				return
			}
		}
	}
	header.Add(name, value)
}

func headerHasToken(header http.Header, name, value string) bool {
	for _, existing := range header.Values(name) {
		for _, token := range strings.Split(existing, ",") {
			if strings.EqualFold(strings.TrimSpace(token), value) {
				return true
			}
		}
	}
	return false
}

func cloneHTTPHeader(header http.Header) http.Header {
	cloned := make(http.Header, len(header))
	for name, values := range header {
		cloned[name] = append([]string(nil), values...)
	}
	return cloned
}

func replaceHTTPHeader(destination, source http.Header) {
	for name := range destination {
		destination.Del(name)
	}
	for name, values := range source {
		destination[name] = append([]string(nil), values...)
	}
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}
