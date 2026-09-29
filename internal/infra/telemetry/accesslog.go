package telemetry

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

var sensitiveQueryParameterNames = map[string]struct{}{
	"access_token":  {},
	"apikey":        {},
	"api_key":       {},
	"authorization": {},
	"client_secret": {},
	"code":          {},
	"jwt":           {},
	"key":           {},
	"password":      {},
	"passwd":        {},
	"refresh_token": {},
	"secret":        {},
	"session":       {},
	"sessionid":     {},
	"sig":           {},
	"signature":     {},
	"token":         {},
}

// RedactRequestURI preserves useful routing diagnostics while preventing URL
// credentials from being copied into access logs.
func RedactRequestURI(requestURL *url.URL) string {
	if requestURL == nil {
		return ""
	}
	path := requestURL.EscapedPath()
	if path == "" {
		path = "/"
	}
	if requestURL.RawQuery == "" {
		if requestURL.ForceQuery {
			return path + "?"
		}
		return path
	}
	query, err := url.ParseQuery(requestURL.RawQuery)
	if err != nil {
		return path + "?redacted=invalid_query"
	}
	for key, values := range query {
		if _, sensitive := sensitiveQueryParameterNames[strings.ToLower(key)]; sensitive {
			for index := range values {
				values[index] = "[REDACTED]"
			}
			query[key] = values
		}
	}
	return path + "?" + query.Encode()
}

type AccessLogConfig struct {
	Enabled      bool
	Path         string
	RotateSizeMB int64
	KeepFiles    int
}

type AccessLogEntry struct {
	Timestamp time.Time
	ClientIP  string
	Method    string
	Path      string
	Protocol  string
	Status    int
	BytesSent int
	Referer   string
	UserAgent string
	RequestID string
	Latency   time.Duration
	Upstream  string
}

type AccessLogger struct {
	mu         sync.Mutex
	path       string
	rotateSize int64
	keepFiles  int
	file       *os.File
	entries    chan AccessLogEntry
}

var accessLogger *AccessLogger

func InitAccessLogger(cfg AccessLogConfig) error {
	if !cfg.Enabled {
		return nil
	}
	if cfg.Path == "" {
		cfg.Path = "./logs/access.log"
	}
	if cfg.RotateSizeMB <= 0 {
		cfg.RotateSizeMB = 100
	}
	if cfg.KeepFiles <= 0 {
		cfg.KeepFiles = 14
	}
	if err := os.MkdirAll(filepath.Dir(cfg.Path), 0755); err != nil {
		return err
	}
	l := &AccessLogger{
		path:       cfg.Path,
		rotateSize: cfg.RotateSizeMB * 1024 * 1024,
		keepFiles:  cfg.KeepFiles,
		entries:    make(chan AccessLogEntry, 10000),
	}
	if err := l.open(); err != nil {
		return err
	}
	accessLogger = l
	go l.run()
	return nil
}

func WriteAccessLog(entry AccessLogEntry) {
	if accessLogger == nil {
		return
	}
	select {
	case accessLogger.entries <- entry:
	default:
		if Logger != nil {
			Logger.Warn("access log queue full; dropping entry")
		}
	}
}

func (l *AccessLogger) run() {
	for entry := range l.entries {
		if err := l.write(entry); err != nil && Logger != nil {
			Logger.Error("failed to write access log", zap.Error(err))
		}
	}
}

func (l *AccessLogger) open() error {
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	l.file = f
	return nil
}

func (l *AccessLogger) write(entry AccessLogEntry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		if err := l.open(); err != nil {
			return err
		}
	}
	if err := l.rotateIfNeeded(); err != nil {
		return err
	}
	_, err := l.file.WriteString(formatAccessLog(entry))
	return err
}

func (l *AccessLogger) rotateIfNeeded() error {
	info, err := l.file.Stat()
	if err != nil || info.Size() < l.rotateSize {
		return err
	}
	_ = l.file.Close()
	for i := l.keepFiles - 1; i >= 1; i-- {
		oldName := fmt.Sprintf("%s.%d", l.path, i)
		newName := fmt.Sprintf("%s.%d", l.path, i+1)
		_ = os.Rename(oldName, newName)
	}
	_ = os.Rename(l.path, l.path+".1")
	return l.open()
}

func formatAccessLog(e AccessLogEntry) string {
	ts := e.Timestamp.Format("02/Jan/2006:15:04:05 -0700")
	referer := e.Referer
	if referer == "" {
		referer = "-"
	}
	upstream := e.Upstream
	if upstream == "" {
		upstream = "-"
	}
	requestLine := escapeLog(e.Method + " " + e.Path + " " + e.Protocol)
	return fmt.Sprintf("%s - - [%s] \"%s\" %d %d \"%s\" \"%s\" req_id=%s rt=%dms upstream=%s\n",
		cleanIP(e.ClientIP),
		ts,
		requestLine,
		e.Status,
		e.BytesSent,
		escapeLog(referer),
		escapeLog(e.UserAgent),
		escapeLog(e.RequestID),
		e.Latency.Milliseconds(),
		escapeLog(upstream),
	)
}

func cleanIP(remote string) string {
	if host, _, err := net.SplitHostPort(remote); err == nil {
		return host
	}
	return remote
}

func escapeLog(v string) string {
	v = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return ' '
		}
		return r
	}, v)
	v = strconv.Quote(v)
	return strings.Trim(v, `"`)
}
