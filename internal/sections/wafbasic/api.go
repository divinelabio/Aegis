package wafbasic

import (
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/divinelab-io/aegis/internal/infra/requestctx"
	"github.com/google/uuid"
)

func (s *Section) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	stats := s.Stats()
	writeJSON(w, map[string]interface{}{"dashboard": map[string]interface{}{
		"total_requests": stats.TotalRequests, "blocked_requests": stats.BlockedRequests,
		"allowed_requests": stats.AllowedRequests, "avg_inspection_ms": stats.AvgLatencyMs,
		"attack_types": []interface{}{}, "history": []interface{}{},
	}})
}

func (s *Section) handleAnalytics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	stats := s.Stats()
	if strings.Contains(r.URL.Path, "/events/") {
		writeJSON(w, map[string]interface{}{"event": nil, "error": "event_not_found"})
		return
	}
	if strings.HasSuffix(r.URL.Path, "/events") {
		writeJSON(w, map[string]interface{}{"events": []interface{}{}, "total": 0})
		return
	}
	writeJSON(w, map[string]interface{}{
		"dashboard": map[string]interface{}{"total_requests": stats.TotalRequests, "blocked_requests": stats.BlockedRequests, "allowed_requests": stats.AllowedRequests},
		"summary":   map[string]interface{}{"total_requests": stats.TotalRequests, "blocked_requests": stats.BlockedRequests},
		"history":   []interface{}{}, "events": []interface{}{}, "top_rules": []interface{}{},
	})
}

func (s *Section) handleCustomRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.mu.RLock()
		rules := append([]CommunityRule(nil), s.customRules...)
		s.mu.RUnlock()
		writeJSON(w, map[string]interface{}{"rules": rules})
	case http.MethodPost:
		var rule CommunityRule
		if err := decodeBoundedJSON(w, r, &rule); err != nil {
			http.Error(w, "invalid custom rule", http.StatusBadRequest)
			return
		}
		if rule.ID == "" {
			rule.ID = uuid.NewString()
		}
		if rule.Name == "" {
			http.Error(w, "custom rule name is required", http.StatusBadRequest)
			return
		}
		if !rule.Enabled {
			rule.Enabled = true
		}
		if _, err := compileCommunityRule(rule); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		for _, existing := range s.customRules {
			if existing.ID == rule.ID {
				s.mu.Unlock()
				http.Error(w, "custom rule already exists", http.StatusConflict)
				return
			}
		}
		s.customRules = append(s.customRules, rule)
		err := s.rebuildCommunityRulesLocked()
		s.mu.Unlock()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_ = s.persistCurrentConfig()
		writeJSON(w, map[string]interface{}{"success": true, "rule": rule})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Section) handleCustomRule(w http.ResponseWriter, r *http.Request) {
	subpath := strings.TrimPrefix(r.URL.Path, "/api/sections/waf_core/rules/custom/")
	subpath = strings.Trim(subpath, "/")
	var isToggle bool
	var id string
	if strings.HasSuffix(subpath, "/enabled") {
		isToggle = true
		id = strings.TrimSuffix(subpath, "/enabled")
	} else {
		id = subpath
	}
	id, _ = url.PathUnescape(id)
	id = strings.Trim(id, "/")
	if id == "" || strings.Contains(id, "/") {
		http.Error(w, "invalid custom rule id", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	index := -1
	for i := range s.customRules {
		if s.customRules[i].ID == id {
			index = i
			break
		}
	}
	if index < 0 {
		s.mu.Unlock()
		http.Error(w, "custom rule not found", http.StatusNotFound)
		return
	}
	if isToggle {
		if r.Method != http.MethodPatch && r.Method != http.MethodPut && r.Method != http.MethodPost {
			s.mu.Unlock()
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var payload struct {
			Enabled bool `json:"enabled"`
		}
		if err := decodeBoundedJSON(w, r, &payload); err != nil {
			s.mu.Unlock()
			http.Error(w, "invalid toggle payload", http.StatusBadRequest)
			return
		}
		s.customRules[index].Enabled = payload.Enabled
		err := s.rebuildCommunityRulesLocked()
		rule := s.customRules[index]
		s.mu.Unlock()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_ = s.persistCurrentConfig()
		writeJSON(w, map[string]interface{}{"success": true, "rule": rule})
		return
	}
	switch r.Method {
	case http.MethodGet:
		rule := s.customRules[index]
		s.mu.Unlock()
		writeJSON(w, map[string]interface{}{"rule": rule})
	case http.MethodPut:
		var rule CommunityRule
		if err := decodeBoundedJSON(w, r, &rule); err != nil {
			s.mu.Unlock()
			http.Error(w, "invalid custom rule", http.StatusBadRequest)
			return
		}
		rule.ID = id
		if _, err := compileCommunityRule(rule); err != nil {
			s.mu.Unlock()
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.customRules[index] = rule
		err := s.rebuildCommunityRulesLocked()
		s.mu.Unlock()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_ = s.persistCurrentConfig()
		writeJSON(w, map[string]interface{}{"success": true, "rule": rule})
	case http.MethodDelete:
		s.customRules = append(s.customRules[:index], s.customRules[index+1:]...)
		err := s.rebuildCommunityRulesLocked()
		s.mu.Unlock()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_ = s.persistCurrentConfig()
		writeJSON(w, map[string]bool{"success": true})
	default:
		s.mu.Unlock()
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Section) rebuildCommunityRulesLocked() error {
	rawRules := make([]string, 0, len(s.customRules))
	for _, rule := range s.customRules {
		if !rule.Enabled {
			continue
		}
		raw, err := compileCommunityRule(rule)
		if err != nil {
			return err
		}
		rawRules = append(rawRules, raw)
	}
	candidate := s.config
	candidate.CustomRules = rawRules
	engine, err := buildWAF(candidate, s.logger)
	if err != nil {
		return err
	}
	s.config, s.waf = candidate, engine
	s.settings["custom_rules"] = rawRules
	s.lastReload, s.lastError = time.Now().UTC(), ""
	return nil
}

func compileCommunityRule(rule CommunityRule) (string, error) {
	if raw := strings.TrimSpace(rule.RawRule); raw != "" {
		if len(raw) > 64<<10 || !strings.HasPrefix(raw, "SecRule ") || strings.ContainsAny(raw, "\r\n") {
			return "", errors.New("raw rules must be one bounded SecRule directive")
		}
		return raw, nil
	}
	if len(rule.Targets) == 0 || len(rule.Targets[0].Patterns) == 0 {
		return "", errors.New("at least one target and pattern are required")
	}
	target := rule.Targets[0]
	variable := mapRuleVariable(target.Zone, target.Field)
	operator := target.Operator
	if operator == "" {
		operator = "@rx"
	}
	allowedOperators := map[string]bool{
		"@rx": true, "@contains": true, "@beginsWith": true, "@endsWith": true, "@streq": true,
		"@ipMatch": true, "@ipMatchFromFile": true, "@pm": true, "@pmFromFile": true,
		"@detectSQLi": true, "@detectXSS": true, "@within": true,
	}
	if !allowedOperators[operator] {
		return "", errors.New("custom rule operator is unsupported")
	}
	if target.Negate && !strings.HasPrefix(operator, "!") {
		operator = "!" + operator
	}
	pattern := secLangValue(target.Patterns[0])
	action := "deny,status:403"
	if rule.Action == "log" {
		action = "pass"
	} else if rule.Action == "allow" {
		action = "allow"
	}
	phase := rule.Phase
	if phase < 1 || phase > 4 {
		phase = 2
	}
	var numericID int
	if n, err := strconv.Atoi(rule.ID); err == nil && n >= 100000 && n <= 999999 {
		numericID = n
	} else {
		numericID = 700000 + int(crc32.ChecksumIEEE([]byte(rule.ID))%99999)
	}
	message := secLangMessage(rule.Message)
	if message == "" {
		message = secLangMessage(rule.Name)
	}
	transformActions := ""
	for _, t := range target.Transforms {
		if mapped := mapTransformName(t); mapped != "" {
			transformActions += ",t:" + mapped
		}
	}
	return fmt.Sprintf(`SecRule %s "%s %s" "id:%d,phase:%d,%s%s,log,msg:'%s'"`, variable, operator, pattern, numericID, phase, action, transformActions, message), nil
}

func mapTransformName(t string) string {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "lowercase":
		return "lowercase"
	case "url_decode", "urldecode":
		return "urlDecodeUni"
	case "html_entity_decode", "htmlentitydecode":
		return "htmlEntityDecode"
	case "base64_decode", "base64decode":
		return "base64Decode"
	case "hex_decode", "hexdecode":
		return "hexDecode"
	case "remove_comments", "removecomments":
		return "removeComments"
	case "remove_whitespace", "removewhitespace":
		return "removeWhitespace"
	case "compress_whitespace", "compresswhitespace":
		return "compressWhitespace"
	case "normalize_path", "normalizepath":
		return "normalizePath"
	case "none":
		return "none"
	default:
		return ""
	}
}

func mapRuleVariable(zone, field string) string {
	cleanField := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' {
			return r
		}
		return -1
	}, field)
	switch strings.ToLower(zone) {
	case "uri", "url":
		return "REQUEST_URI"
	case "path":
		return "REQUEST_FILENAME"
	case "method":
		return "REQUEST_METHOD"
	case "client_ip", "ip", "remote_addr":
		return "REMOTE_ADDR"
	case "headers", "header":
		if cleanField != "" {
			return "REQUEST_HEADERS:" + cleanField
		}
		return "REQUEST_HEADERS"
	case "body", "body_json":
		return "REQUEST_BODY"
	case "cookies", "cookie":
		if cleanField != "" {
			return "REQUEST_COOKIES:" + cleanField
		}
		return "REQUEST_COOKIES"
	default:
		if cleanField != "" {
			return "ARGS:" + cleanField
		}
		return "ARGS"
	}
}

func secLangValue(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	value = strings.ReplaceAll(value, "\r", "")
	value = strings.ReplaceAll(value, "\n", "")
	return value
}

func secLangMessage(value string) string {
	value = strings.ReplaceAll(value, `'`, "")
	value = strings.ReplaceAll(value, "\r", "")
	value = strings.ReplaceAll(value, "\n", "")
	if len(value) > 200 {
		value = value[:200]
	}
	return value
}

func (s *Section) handleCRSRules(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	root := s.config.Engine.CRSPath
	disabled := append([]string(nil), s.config.DisabledCRS...)
	s.mu.RUnlock()
	files, err := allCRSFiles(root)
	if err != nil {
		http.Error(w, "CRS rules are unavailable", http.StatusServiceUnavailable)
		return
	}
	filename := filepath.Base(r.URL.Query().Get("file"))
	if r.Method == http.MethodGet && filename != "." && filename != "" && r.URL.Query().Get("content") == "true" {
		path, ok := findCRSFile(files, filename)
		if !ok {
			http.Error(w, "CRS file not found", http.StatusNotFound)
			return
		}
		content, err := os.ReadFile(path)
		if err != nil || len(content) > 2<<20 {
			http.Error(w, "CRS file is not readable", http.StatusUnprocessableEntity)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write(content)
		return
	}
	if r.Method == http.MethodGet {
		disabledSet := map[string]bool{}
		for _, name := range disabled {
			disabledSet[filepath.Base(name)] = true
		}
		items := make([]map[string]interface{}, 0, len(files))
		for _, path := range files {
			name := filepath.Base(path)
			items = append(items, map[string]interface{}{"name": name, "enabled": !disabledSet[name], "group": crsGroup(name), "category": crsCategory(name), "status": "healthy"})
		}
		writeJSON(w, map[string]interface{}{"files": items})
		return
	}
	if r.Method != http.MethodPost || filename == "." || filename == "" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if _, ok := findCRSFile(files, filename); !ok {
		http.Error(w, "CRS file not found", http.StatusNotFound)
		return
	}
	action := r.URL.Query().Get("action")
	s.mu.Lock()
	set := map[string]bool{}
	for _, name := range s.config.DisabledCRS {
		set[filepath.Base(name)] = true
	}
	if action == "disable" {
		set[filename] = true
	} else if action == "enable" {
		delete(set, filename)
	} else {
		s.mu.Unlock()
		http.Error(w, "action must be enable or disable", http.StatusBadRequest)
		return
	}
	names := make([]string, 0, len(set))
	for name := range set {
		names = append(names, name)
	}
	sort.Strings(names)
	candidate := s.config
	candidate.DisabledCRS = names
	engine, err := buildWAF(candidate, s.logger)
	if err == nil {
		s.config, s.waf = candidate, engine
		s.settings["disabled_crs"] = names
	}
	s.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_ = s.persistCurrentConfig()
	writeJSON(w, map[string]interface{}{"success": true, "file": filename, "enabled": action == "enable"})
}

type crsBulkRequest struct {
	Action string   `json:"action"`
	Files  []string `json:"files"`
}

func (s *Section) handleCRSRulesBulk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req crsBulkRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	req.Action = strings.ToLower(strings.TrimSpace(req.Action))
	if req.Action != "enable" && req.Action != "disable" {
		http.Error(w, "action must be enable or disable", http.StatusBadRequest)
		return
	}
	if len(req.Files) == 0 {
		writeJSON(w, map[string]interface{}{"changed": []string{}, "skipped": []string{}})
		return
	}

	s.mu.Lock()
	set := map[string]bool{}
	for _, name := range s.config.DisabledCRS {
		set[filepath.Base(name)] = true
	}

	changed := make([]string, 0, len(req.Files))
	skipped := make([]string, 0)
	seen := make(map[string]bool, len(req.Files))

	for _, rawFile := range req.Files {
		file := filepath.Base(strings.TrimSpace(rawFile))
		if file == "" || file == "." || seen[file] {
			continue
		}
		seen[file] = true

		if req.Action == "disable" {
			if set[file] {
				skipped = append(skipped, file)
			} else {
				set[file] = true
				changed = append(changed, file)
			}
		} else { // enable
			if set[file] {
				delete(set, file)
				changed = append(changed, file)
			} else {
				skipped = append(skipped, file)
			}
		}
	}

	if len(changed) > 0 {
		names := make([]string, 0, len(set))
		for name := range set {
			names = append(names, name)
		}
		sort.Strings(names)
		candidate := s.config
		candidate.DisabledCRS = names
		engine, err := buildWAF(candidate, s.logger)
		if err == nil {
			s.config, s.waf = candidate, engine
			s.settings["disabled_crs"] = names
		} else {
			s.mu.Unlock()
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	s.mu.Unlock()
	if len(changed) > 0 {
		_ = s.persistCurrentConfig()
	}

	writeJSON(w, map[string]interface{}{
		"changed": changed,
		"skipped": skipped,
	})
}

func allCRSFiles(root string) ([]string, error) {
	if _, err := os.Stat(root); os.IsNotExist(err) {
		if info, err := os.Stat("data/rules/crs"); err == nil && info.IsDir() {
			root = "data/rules/crs"
		} else if info, err := os.Stat("rules/crs"); err == nil && info.IsDir() {
			root = "rules/crs"
		}
	}
	files := []string{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".conf") {
			files = append(files, path)
		}
		return nil
	})
	sort.Strings(files)
	return files, err
}

func findCRSFile(files []string, name string) (string, bool) {
	for _, path := range files {
		if filepath.Base(path) == name {
			return path, true
		}
	}
	return "", false
}

func crsGroup(name string) string {
	parts := strings.Split(strings.TrimSuffix(name, ".conf"), "-")
	if len(parts) >= 3 {
		return strings.ReplaceAll(strings.Title(strings.ToLower(strings.Join(parts[2:], " "))), "Crs", "CRS")
	}
	return "Other Rules"
}

func crsCategory(name string) string {
	if strings.HasPrefix(name, "RESPONSE-") {
		return "response"
	}
	if strings.HasPrefix(name, "REQUEST-") {
		return "request"
	}
	return "other"
}

func (s *Section) handleProfiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		paidFeatureHandler(w, r)
		return
	}
	s.mu.RLock()
	profile := map[string]interface{}{"id": "community-default", "name": "Community CRS", "description": "OWASP CRS Community policy", "builtin": true, "paranoia_level": s.config.Engine.ParanoiaLevel, "anomaly_threshold": s.config.Engine.AnomalyThreshold}
	s.mu.RUnlock()
	writeJSON(w, map[string]interface{}{"profiles": []interface{}{profile}, "policies": []interface{}{profile}})
}

func (s *Section) handleExclusions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.mu.RLock()
		values := append([]CommunityExclusion(nil), s.exclusions...)
		s.mu.RUnlock()
		writeJSON(w, map[string]interface{}{"exclusions": values})
	case http.MethodPost:
		var exclusion CommunityExclusion
		if err := decodeBoundedJSON(w, r, &exclusion); err != nil {
			http.Error(w, "invalid exclusion", http.StatusBadRequest)
			return
		}
		if exclusion.ID == "" {
			exclusion.ID = uuid.NewString()
		}
		if exclusion.CreatedAt.IsZero() {
			exclusion.CreatedAt = time.Now().UTC()
		}
		s.mu.Lock()
		s.exclusions = append(s.exclusions, exclusion)
		s.mu.Unlock()
		_ = s.persistCurrentConfig()
		writeJSON(w, map[string]interface{}{"success": true, "exclusion": exclusion})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Section) handleExclusion(w http.ResponseWriter, r *http.Request) {
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/sections/waf_core/exclusions/"), "/")
	s.mu.Lock()
	index := -1
	for i := range s.exclusions {
		if s.exclusions[i].ID == id {
			index = i
			break
		}
	}
	if index < 0 {
		s.mu.Unlock()
		http.Error(w, "exclusion not found", http.StatusNotFound)
		return
	}
	switch r.Method {
	case http.MethodGet:
		value := s.exclusions[index]
		s.mu.Unlock()
		writeJSON(w, map[string]interface{}{"exclusion": value})
	case http.MethodPut:
		var value CommunityExclusion
		if err := decodeBoundedJSON(w, r, &value); err != nil {
			s.mu.Unlock()
			http.Error(w, "invalid exclusion", http.StatusBadRequest)
			return
		}
		value.ID, value.CreatedAt = id, s.exclusions[index].CreatedAt
		s.exclusions[index] = value
		s.mu.Unlock()
		_ = s.persistCurrentConfig()
		writeJSON(w, map[string]interface{}{"success": true, "exclusion": value})
	case http.MethodDelete:
		s.exclusions = append(s.exclusions[:index], s.exclusions[index+1:]...)
		s.mu.Unlock()
		_ = s.persistCurrentConfig()
		writeJSON(w, map[string]bool{"success": true})
	default:
		s.mu.Unlock()
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Section) handleExclusionSuggest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, map[string]interface{}{"suggestions": []interface{}{}})
}

func (s *Section) excluded(r *http.Request) bool {
	s.mu.RLock()
	values := append([]CommunityExclusion(nil), s.exclusions...)
	s.mu.RUnlock()
	for _, exclusion := range values {
		if !exclusion.Enabled || exclusionExpired(exclusion.ExpiresAt) {
			continue
		}
		// A rule-specific exclusion (exclusion.RuleID != "") targets specific rules,
		// and does not globally bypass the entire WAF engine.
		if strings.TrimSpace(exclusion.RuleID) != "" {
			continue
		}
		hasPaths := len(exclusion.Paths) > 0
		hasIPs := len(exclusion.IPs) > 0
		if !hasPaths && !hasIPs {
			continue
		}
		pathMatched := false
		if hasPaths {
			for _, pattern := range exclusion.Paths {
				if pathMatch(pattern, r.URL.Path) {
					pathMatched = true
					break
				}
			}
		}
		ipMatched := false
		if hasIPs {
			clientIP := requestctx.ClientIP(r)
			if clientIP == "" {
				clientIP = remoteHost(r.RemoteAddr)
			}
			parsedClientIP := net.ParseIP(clientIP)
			for _, value := range exclusion.IPs {
				value = strings.TrimSpace(value)
				if value == clientIP {
					ipMatched = true
					break
				}
				if parsedClientIP != nil {
					if _, network, err := net.ParseCIDR(value); err == nil && network.Contains(parsedClientIP) {
						ipMatched = true
						break
					}
				}
			}
		}
		if hasPaths && hasIPs {
			if pathMatched && ipMatched {
				return true
			}
		} else if hasPaths {
			if pathMatched {
				return true
			}
		} else if hasIPs {
			if ipMatched {
				return true
			}
		}
	}
	return false
}

func exclusionExpired(raw string) bool {
	if raw == "" {
		return false
	}
	value, err := time.Parse(time.RFC3339, raw)
	return err == nil && time.Now().After(value)
}

func pathMatch(pattern, urlPath string) bool {
	matched, _ := path.Match(pattern, urlPath)
	return matched || strings.HasSuffix(pattern, "*") && strings.HasPrefix(urlPath, strings.TrimSuffix(pattern, "*"))
}

func (s *Section) handleConfigTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	var testReq struct {
		Payload string `json:"payload"`
		Method  string `json:"method"`
		URI     string `json:"uri"`
		Rule    string `json:"rule"`
		Request struct {
			Method  string            `json:"method"`
			URI     string            `json:"uri"`
			Headers map[string]string `json:"headers"`
			Body    string            `json:"body"`
		} `json:"request"`
	}
	_ = json.Unmarshal(bodyBytes, &testReq)

	s.mu.RLock()
	engine := s.waf
	s.mu.RUnlock()

	if engine == nil {
		writeJSON(w, map[string]interface{}{"success": true, "blocked": false, "message": "WAF engine is not initialized"})
		return
	}

	testURI := "/test"
	if testReq.URI != "" {
		testURI = testReq.URI
	} else if testReq.Request.URI != "" {
		testURI = testReq.Request.URI
	}
	testMethod := "POST"
	if testReq.Method != "" {
		testMethod = testReq.Method
	} else if testReq.Request.Method != "" {
		testMethod = testReq.Request.Method
	}
	testBody := testReq.Payload
	if testBody == "" && testReq.Request.Body != "" {
		testBody = testReq.Request.Body
	}
	if testBody == "" && len(bodyBytes) > 0 && !strings.HasPrefix(strings.TrimSpace(string(bodyBytes)), "{") {
		testBody = string(bodyBytes)
	}

	tx := engine.NewTransaction()
	defer tx.Close()
	tx.ProcessConnection("127.0.0.1", 0, "", 0)
	tx.ProcessURI(testURI, testMethod, "HTTP/1.1")
	tx.AddRequestHeader("Host", "localhost")
	hasUA := false
	hasCT := false
	for k, v := range testReq.Request.Headers {
		if strings.EqualFold(k, "User-Agent") {
			hasUA = true
		}
		if strings.EqualFold(k, "Content-Type") {
			hasCT = true
		}
		tx.AddRequestHeader(k, v)
	}
	if !hasUA {
		tx.AddRequestHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AegisTest/1.0")
	}
	if !hasCT && testBody != "" {
		tx.AddRequestHeader("Content-Type", "application/x-www-form-urlencoded")
	}
	if interruption := tx.ProcessRequestHeaders(); interruption != nil {
		writeJSON(w, map[string]interface{}{
			"success": true,
			"blocked": true,
			"matched": true,
			"action":  interruption.Action,
			"status":  interruption.Status,
			"rule_id": interruption.RuleID,
			"message": "payload blocked by WAF header inspection",
		})
		return
	}
	if testBody != "" {
		_, _, _ = tx.WriteRequestBody([]byte(testBody))
		if interruption, _ := tx.ProcessRequestBody(); interruption != nil {
			writeJSON(w, map[string]interface{}{
				"success": true,
				"blocked": true,
				"matched": true,
				"action":  interruption.Action,
				"status":  interruption.Status,
				"rule_id": interruption.RuleID,
				"message": "payload blocked by WAF body inspection",
			})
			return
		}
	}
	writeJSON(w, map[string]interface{}{
		"success": true,
		"blocked": false,
		"matched": false,
		"message": "payload allowed by WAF",
	})
}

func paidFeatureHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": "feature_not_entitled"})
}

func decodeBoundedJSON(w http.ResponseWriter, r *http.Request, target interface{}) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

func numberAsInt(value interface{}) (int, bool) {
	switch number := value.(type) {
	case int:
		return number, true
	case float64:
		return int(number), true
	case json.Number:
		value, err := strconv.Atoi(number.String())
		return value, err == nil
	default:
		return 0, false
	}
}
