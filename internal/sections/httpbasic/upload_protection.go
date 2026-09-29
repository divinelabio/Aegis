package httpbasic

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"mime"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// UploadAction represents the enforcement outcome of an upload inspection.
type UploadAction string

const (
	UploadActionAllow  UploadAction = "allow"
	UploadActionDetect UploadAction = "detect"
	UploadActionBlock  UploadAction = "block"
)

// UploadProtectionConfig defines policies for file upload security.
type UploadProtectionConfig struct {
	Enabled            bool                `json:"enabled" mapstructure:"enabled"`
	Mode               string              `json:"mode" mapstructure:"mode"` // "allow", "detect", "block"
	MaxFiles           int                 `json:"max_files" mapstructure:"max_files"`
	MaxFileSize        int64               `json:"max_file_size" mapstructure:"max_file_size"`
	MaxTotalUploadSize int64               `json:"max_total_upload_size" mapstructure:"max_total_upload_size"`
	MaxFilenameLength  int                 `json:"max_filename_length" mapstructure:"max_filename_length"`
	InspectFirstBytes  int64               `json:"inspect_first_bytes" mapstructure:"inspect_first_bytes"`
	AllowedExtensions  []string            `json:"allowed_extensions" mapstructure:"allowed_extensions"`
	BlockedExtensions  []string            `json:"blocked_extensions" mapstructure:"blocked_extensions"`
	MimePolicy         string              `json:"mime_policy" mapstructure:"mime_policy"` // "validate", "allow"
	ArchivePolicy      ArchivePolicyConfig `json:"archive_policy" mapstructure:"archive_policy"`
	ContentRules       UploadContentRules  `json:"content_rules" mapstructure:"content_rules"`
}

// ArchivePolicyConfig defines archive inspection and zip-bomb prevention.
type ArchivePolicyConfig struct {
	Enabled                bool  `json:"enabled" mapstructure:"enabled"`
	MaxEntries             int   `json:"max_entries" mapstructure:"max_entries"`
	MaxExpandedSize        int64 `json:"max_expanded_size" mapstructure:"max_expanded_size"`
	MaxCompressionRatio    int   `json:"max_compression_ratio" mapstructure:"max_compression_ratio"`
	BlockNestedArchives    bool  `json:"block_nested_archives" mapstructure:"block_nested_archives"`
	BlockEncryptedArchives bool  `json:"block_encrypted_archives" mapstructure:"block_encrypted_archives"`
	BlockTraversalPaths    bool  `json:"block_traversal_paths" mapstructure:"block_traversal_paths"`
}

// UploadContentRules enables detection of dangerous payloads.
type UploadContentRules struct {
	DetectSVGScript       bool `json:"detect_svg_script" mapstructure:"detect_svg_script"`
	DetectHTMLUpload      bool `json:"detect_html_upload" mapstructure:"detect_html_upload"`
	DetectServerSideCode  bool `json:"detect_server_side_code" mapstructure:"detect_server_side_code"`
	DetectMacroDocuments  bool `json:"detect_macro_documents" mapstructure:"detect_macro_documents"`
	DetectExecutableBytes bool `json:"detect_executable_bytes" mapstructure:"detect_executable_bytes"`
	DetectPDFExploits     bool `json:"detect_pdf_exploits" mapstructure:"detect_pdf_exploits"`
	DetectHighEntropy     bool `json:"detect_high_entropy" mapstructure:"detect_high_entropy"`
}

// DefaultUploadProtectionConfig provides production defaults for Community Edition.
func DefaultUploadProtectionConfig() UploadProtectionConfig {
	return UploadProtectionConfig{
		Enabled:            true,
		Mode:               string(UploadActionDetect),
		MaxFiles:           20,
		MaxFileSize:        10 * 1024 * 1024,
		MaxTotalUploadSize: 50 * 1024 * 1024,
		MaxFilenameLength:  180,
		InspectFirstBytes:  8192,
		AllowedExtensions:  []string{},
		BlockedExtensions:  []string{".php", ".phtml", ".jsp", ".jspx", ".asp", ".aspx", ".exe", ".dll", ".sh", ".bat", ".cmd", ".ps1"},
		MimePolicy:         "validate",
		ArchivePolicy: ArchivePolicyConfig{
			Enabled:                true,
			MaxEntries:             512,
			MaxExpandedSize:        100 * 1024 * 1024,
			MaxCompressionRatio:    100,
			BlockNestedArchives:    true,
			BlockEncryptedArchives: true,
			BlockTraversalPaths:    true,
		},
		ContentRules: UploadContentRules{
			DetectSVGScript:       true,
			DetectHTMLUpload:      true,
			DetectServerSideCode:  true,
			DetectMacroDocuments:  true,
			DetectExecutableBytes: true,
			DetectPDFExploits:     true,
			DetectHighEntropy:     true,
		},
	}
}

// UploadFinding describes a single policy violation detected during inspection.
type UploadFinding struct {
	RuleID          string `json:"rule_id"`
	RuleName        string `json:"rule_name"`
	Category        string `json:"category"`
	Severity        string `json:"severity"`
	MatchedLocation string `json:"matched_location"`
	SafeExcerpt     string `json:"safe_excerpt"`
	Confidence      int    `json:"confidence"`
}

// UploadInspectionResult aggregates findings and final disposition for an upload.
type UploadInspectionResult struct {
	Layer          string          `json:"layer"`
	Action         string          `json:"action"`
	Findings       []UploadFinding `json:"findings,omitempty"`
	BytesInspected int64           `json:"bytes_inspected"`
	Truncated      bool            `json:"truncated"`
	InspectionTime time.Duration   `json:"inspection_time"`
}

func (r UploadInspectionResult) Blocked() bool {
	return r.Action == string(UploadActionBlock)
}

// UploadProtectionEngine performs multi-layered file upload analysis.
type UploadProtectionEngine struct {
	config UploadProtectionConfig
}

func NewUploadProtectionEngine(cfg UploadProtectionConfig) *UploadProtectionEngine {
	return &UploadProtectionEngine{config: cfg}
}

func (e *UploadProtectionEngine) Inspect(r *http.Request, body []byte, truncated bool) (result UploadInspectionResult) {
	start := time.Now()
	defer func() {
		result.InspectionTime = time.Since(start)
	}()

	result = UploadInspectionResult{
		Layer:          "upload_protection",
		Action:         string(UploadActionAllow),
		BytesInspected: int64(len(body)),
		Truncated:      truncated,
	}

	if e == nil || !e.config.Enabled || !strings.Contains(r.Header.Get("Content-Type"), "multipart/form-data") {
		return result
	}

	mode := normalizeUploadMode(e.config.Mode)
	if mode == string(UploadActionAllow) {
		return result
	}

	_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || params["boundary"] == "" {
		e.addFinding(&result, "upload.multipart.malformed", "Malformed multipart upload", "multipart", "medium", "request.multipart", r.Header.Get("Content-Type"), 76)
		if mode == string(UploadActionBlock) {
			result.Action = string(UploadActionBlock)
		}
		return result
	}

	reader := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	files := 0
	total := int64(0)
	seen := map[string]bool{}

	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			e.addFinding(&result, "upload.multipart.malformed", "Malformed multipart upload", "multipart", "medium", "request.multipart", err.Error(), 76)
			break
		}

		filename := part.FileName()
		if filename == "" {
			continue
		}

		files++
		if files > e.config.MaxFiles && e.config.MaxFiles > 0 {
			e.addFinding(&result, "upload.max_files", "Upload file count exceeds policy", "limits", "medium", "request.files", fmt.Sprintf("files=%d", files), 85)
		}

		cleanName := filepath.Base(filename)
		lowerClean := strings.ToLower(cleanName)
		if seen[lowerClean] {
			e.addFinding(&result, "upload.duplicate_filename", "Duplicate upload filename", "filename", "low", "request.files."+cleanName, cleanName, 68)
		}
		seen[lowerClean] = true

		limit := e.config.MaxFileSize
		if limit <= 0 {
			limit = 50 * 1024 * 1024
		}
		data, _ := io.ReadAll(io.LimitReader(part, limit+1))
		size := int64(len(data))
		total += size

		if size > limit {
			e.addFinding(&result, "upload.max_file_size", "Uploaded file exceeds per-file policy", "limits", "medium", "request.files."+cleanName, cleanName, 85)
		}

		e.inspectFilename(cleanName, &result)
		inspectBytes := e.config.InspectFirstBytes
		if inspectBytes <= 0 {
			inspectBytes = 8192
		}
		e.inspectContent(cleanName, part.Header.Get("Content-Type"), data[:minInt(len(data), int(inspectBytes))], &result)
		e.inspectArchive(cleanName, data, &result)
	}

	if e.config.MaxTotalUploadSize > 0 && total > e.config.MaxTotalUploadSize {
		e.addFinding(&result, "upload.max_total_size", "Upload total size exceeds policy", "limits", "medium", "request.files", fmt.Sprintf("total=%d", total), 86)
	}

	if mode == string(UploadActionBlock) && len(result.Findings) > 0 {
		result.Action = string(UploadActionBlock)
	}
	return result
}

func (e *UploadProtectionEngine) addFinding(result *UploadInspectionResult, ruleID, name, category, severity, location, excerpt string, confidence int) {
	result.Action = dominantUploadAction(result.Action, string(UploadActionDetect))
	result.Findings = append(result.Findings, UploadFinding{
		RuleID:          ruleID,
		RuleName:        name,
		Category:        category,
		Severity:        severity,
		MatchedLocation: location,
		SafeExcerpt:     safeUploadExcerpt(excerpt),
		Confidence:      confidence,
	})
}

func (e *UploadProtectionEngine) inspectFilename(filename string, result *UploadInspectionResult) {
	lower := strings.ToLower(filename)
	if e.config.MaxFilenameLength > 0 && len(filename) > e.config.MaxFilenameLength {
		e.addFinding(result, "upload.filename.length", "Upload filename exceeds policy", "filename", "medium", "request.files."+filename, filename, 80)
	}
	if strings.Contains(filename, "\x00") || strings.Contains(filename, "../") || strings.Contains(filename, `..\`) || filename != filepath.Base(filename) {
		e.addFinding(result, "upload.filename.path_traversal", "Suspicious upload filename path", "filename", "high", "request.files."+filename, filename, 90)
	}
	ext := filepath.Ext(lower)
	if len(e.config.AllowedExtensions) > 0 && !stringInSlice(ext, e.config.AllowedExtensions) {
		e.addFinding(result, "upload.extension.not_allowed", "Upload extension is not allowlisted", "extension", "medium", "request.files."+filename, filename, 82)
	}
	for _, blocked := range e.config.BlockedExtensions {
		blocked = strings.ToLower(strings.TrimSpace(blocked))
		if blocked != "" && (ext == blocked || strings.Contains(lower, blocked+".")) {
			e.addFinding(result, "upload.extension.blocked", "Blocked upload extension", "extension", "high", "request.files."+filename, filename, 92)
		}
	}
	if strings.Count(lower, ".") >= 2 {
		e.addFinding(result, "upload.extension.double", "Double extension upload", "extension", "medium", "request.files."+filename, filename, 80)
	}
}

func (e *UploadProtectionEngine) inspectContent(filename, declared string, data []byte, result *UploadInspectionResult) {
	if len(data) == 0 {
		e.addFinding(result, "upload.empty_file", "Empty uploaded file", "content", "low", "request.files."+filename, filename, 55)
		return
	}
	detected := http.DetectContentType(data)
	if e.config.MimePolicy == "validate" && declared != "" && !sameMimeFamily(declared, detected) {
		e.addFinding(result, "upload.mime.mismatch", "Upload MIME type does not match file content", "mime", "medium", "request.files."+filename, declared+" -> "+detected, 82)
	}

	if e.config.ContentRules.DetectExecutableBytes {
		if isExec, detail := isExecutableBinary(data); isExec {
			e.addFinding(result, "upload.content.executable", "Executable upload content ("+detail+")", "content", "critical", "request.files."+filename, detail, 95)
		}
	}

	if e.config.ContentRules.DetectServerSideCode {
		if isCode, detail := isServerSideCode(data); isCode {
			e.addFinding(result, "upload.content.server_code", "Server-side code in upload ("+detail+")", "content", "critical", "request.files."+filename, detail, 94)
		}
	}

	if e.config.ContentRules.DetectMacroDocuments {
		if isMacro, detail := isMacroDocument(filename, data); isMacro {
			e.addFinding(result, "upload.content.macro", "Macro-capable document upload ("+detail+")", "content", "high", "request.files."+filename, detail, 88)
		}
	}

	if e.config.ContentRules.DetectSVGScript {
		if isSVGScript, detail := isScriptableSVG(filename, data); isSVGScript {
			e.addFinding(result, "upload.content.svg_script", "SVG upload contains scriptable content ("+detail+")", "content", "high", "request.files."+filename, detail, 92)
		}
	}

	if e.config.ContentRules.DetectHTMLUpload {
		if isHTML, detail := isDisguisedHTML(filename, data); isHTML {
			e.addFinding(result, "upload.content.html", "HTML/script upload content ("+detail+")", "content", "medium", "request.files."+filename, detail, 85)
		}
	}

	if e.config.ContentRules.DetectPDFExploits {
		if isPDF, detail := isPDFExploit(filename, data); isPDF {
			e.addFinding(result, "upload.content.pdf_exploit", "Malicious PDF content ("+detail+")", "content", "high", "request.files."+filename, detail, 92)
		}
	}

	if e.config.ContentRules.DetectHighEntropy {
		if isEntropy, detail := isHighEntropyPayload(filename, data); isEntropy {
			e.addFinding(result, "upload.content.high_entropy", "High-entropy obfuscated payload ("+detail+")", "content", "high", "request.files."+filename, detail, 88)
		}
	}
}

func (e *UploadProtectionEngine) inspectArchive(filename string, data []byte, result *UploadInspectionResult) {
	if !e.config.ArchivePolicy.Enabled {
		return
	}
	lower := strings.ToLower(filename)
	if strings.HasSuffix(lower, ".zip") {
		reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return
		}
		expansionLimit := archiveExpansionLimit(int64(len(data)), e.config.ArchivePolicy.MaxExpandedSize, e.config.ArchivePolicy.MaxCompressionRatio)
		expanded := int64(0)
		for i, file := range reader.File {
			if e.config.ArchivePolicy.MaxEntries > 0 && i >= e.config.ArchivePolicy.MaxEntries {
				e.addFinding(result, "upload.archive.entries", "Archive entry count exceeds policy", "archive", "medium", "request.files."+filename, filename, 84)
				break
			}
			if (expansionLimit > 0 && file.UncompressedSize64 > uint64(expansionLimit)) || saturatingArchiveSizeAdd(expanded, file.UncompressedSize64) > expansionLimit {
				e.addFinding(result, "upload.archive.zip_bomb", "Archive expansion ratio exceeds policy", "archive", "critical", "request.files."+filename, filename, 95)
				return
			}
			if e.config.ArchivePolicy.BlockEncryptedArchives && (file.Flags&0x1 != 0) {
				e.addFinding(result, "upload.archive.encrypted", "Archive contains password-protected or encrypted file", "archive", "high", "request.files."+filename, file.Name, 90)
			}
			if e.config.ArchivePolicy.BlockTraversalPaths && unsafeArchivePath(file.Name) {
				e.addFinding(result, "upload.archive.path_traversal", "Archive contains directory traversal path (ZipSlip)", "archive", "critical", "request.files."+filename, file.Name, 95)
			}
			if e.config.ArchivePolicy.BlockNestedArchives && isArchiveName(file.Name) {
				e.addFinding(result, "upload.archive.nested", "Archive contains nested archive", "archive", "medium", "request.files."+filename, file.Name, 80)
			}
			if isExecutableName(file.Name) {
				e.addFinding(result, "upload.archive.executable", "Archive contains executable file", "archive", "high", "request.files."+filename, file.Name, 88)
			}
			entry, openErr := file.Open()
			if openErr != nil {
				continue
			}
			remaining := expansionLimit - expanded
			copied, _ := io.Copy(io.Discard, io.LimitReader(entry, remaining+1))
			_ = entry.Close()
			expanded += copied
			if expansionLimit > 0 && expanded > expansionLimit {
				e.addFinding(result, "upload.archive.zip_bomb", "Archive expansion ratio exceeds policy", "archive", "critical", "request.files."+filename, filename, 95)
				return
			}
		}
		return
	}

	if strings.HasSuffix(lower, ".tar") || strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz") {
		var reader io.Reader = bytes.NewReader(data)
		if strings.HasSuffix(lower, ".gz") || strings.HasSuffix(lower, ".tgz") {
			gz, err := gzip.NewReader(reader)
			if err != nil {
				return
			}
			defer gz.Close()
			reader = gz
		}
		expansionLimit := archiveExpansionLimit(int64(len(data)), e.config.ArchivePolicy.MaxExpandedSize, e.config.ArchivePolicy.MaxCompressionRatio)
		limited := &io.LimitedReader{R: reader, N: expansionLimit + 1}
		tr := tar.NewReader(limited)
		entries := 0
		for {
			header, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				break
			}
			entries++
			if e.config.ArchivePolicy.MaxEntries > 0 && entries > e.config.ArchivePolicy.MaxEntries {
				e.addFinding(result, "upload.archive.entries", "Archive entry count exceeds policy", "archive", "medium", "request.files."+filename, filename, 84)
				break
			}
			if e.config.ArchivePolicy.BlockTraversalPaths && unsafeArchivePath(header.Name) {
				e.addFinding(result, "upload.archive.path_traversal", "Archive contains directory traversal path (ZipSlip)", "archive", "critical", "request.files."+filename, header.Name, 95)
			}
			if e.config.ArchivePolicy.BlockNestedArchives && isArchiveName(header.Name) {
				e.addFinding(result, "upload.archive.nested", "Archive contains nested archive", "archive", "medium", "request.files."+filename, header.Name, 80)
			}
			if isExecutableName(header.Name) {
				e.addFinding(result, "upload.archive.executable", "Archive contains executable file", "archive", "high", "request.files."+filename, header.Name, 88)
			}
		}
	}
}

// Detection patterns and inspection helpers
var (
	phpScriptPattern        = regexp.MustCompile(`(?i)(<\?php|<\?=|<\?[\s\r\n])`)
	phpDangerousFuncPattern = regexp.MustCompile(`(?i)\b(system|passthru|shell_exec|proc_open|popen|pcntl_exec|create_function)\s*\(`)
	phpEvalPattern          = regexp.MustCompile(`(?i)\b(eval|assert)\s*\(|(?i)\$_(?:GET|POST|COOKIE|REQUEST|SERVER)\[[^\]]+\]\s*\(`)
	phpObfuscationPattern   = regexp.MustCompile(`(?i)\b(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)\s*\(`)

	aspServerPattern       = regexp.MustCompile(`(?i)(<%[@=]?|<script\s+[^>]*runat\s*=\s*["']?server|\bSystem\.Diagnostics\.Process\b|\bcmd\.exe\s+\/c\b|\bpowershell(?:\.exe)?\s+-[eE])`)
	jspServerPattern       = regexp.MustCompile(`(?i)(<%@\s*page|\bRuntime\.getRuntime\(\)\.exec\s*\(|\bProcessBuilder\s*\()`)
	scriptShebangPattern   = regexp.MustCompile(`(?i)^#!\s*/(?:usr/)?(?:local/)?bin/(?:env\s+)?(python[0-9.]*|bash|sh|zsh|dash|perl|ruby|node|php)`)
	pythonExecutionPattern = regexp.MustCompile(`(?is)\bimport\s+(?:os|subprocess|pty|socket)\b.*?(?:\bsubprocess\.(?:Popen|call|check_output)|\bos\.(?:system|popen|exec))\b`)
	nodeExecutionPattern   = regexp.MustCompile(`(?i)\brequire\s*\(\s*['"]child_process['"]\s*\)`)

	ole2Header = []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}
	zipHeader  = []byte{0x50, 0x4B, 0x03, 0x04}

	macroFileExtensions = map[string]bool{
		".docm": true, ".xlsm": true, ".pptm": true, ".dotm": true, ".xltm": true, ".potm": true,
	}

	oleMacroIndicators = [][]byte{
		[]byte("_VBA_PROJECT_CUR"), []byte("VBA"), []byte("dir"), []byte("PROJECT"),
		[]byte("AutoExec"), []byte("AutoOpen"), []byte("Workbook_Open"), []byte("Document_Open"),
	}

	svgTagPattern    = regexp.MustCompile(`(?i)<\s*svg\b`)
	svgEventPattern  = regexp.MustCompile(`(?i)\bon[a-z]{3,15}\s*=`)
	svgScriptPattern = regexp.MustCompile(`(?i)<\s*script\b`)
	svgPseudoPattern = regexp.MustCompile(`(?i)(?:href|xlink:href|src)\s*=\s*["']?\s*(?:(?:javascript|vbscript):|data:(?:text/html|application/xhtml\+xml))`)
	svgForeignObject = regexp.MustCompile(`(?i)<\s*foreignObject\b`)
	svgAnimateHref   = regexp.MustCompile(`(?i)<\s*(?:animate|set)\b[^>]*\battributeName\s*=\s*["']?(?:href|xlink:href)["']?[^>]*\b(?:values|to)\s*=\s*["']?javascript:`)
	svgXXEPattern    = regexp.MustCompile(`(?i)<!ENTITY\b[^>]*\b(?:SYSTEM|PUBLIC)\b`)

	htmlDocPattern       = regexp.MustCompile(`(?i)(<!DOCTYPE\s+html|<\s*html\b|<\s*head\b|<\s*body\b)`)
	htmlRefreshPattern   = regexp.MustCompile(`(?i)<\s*meta\s+[^>]*http-equiv\s*=\s*["']?refresh["']?`)
	htmlIframePattern    = regexp.MustCompile(`(?i)<\s*iframe\b`)
	htmlFormPattern      = regexp.MustCompile(`(?i)<\s*form\b[^>]*action\s*=\s*["'][^"']+["'][^>]*>`)
	htmlPasswordPattern  = regexp.MustCompile(`(?i)<\s*input\b[^>]*type\s*=\s*["']?password["']?`)
	htmlScriptTagPattern = regexp.MustCompile(`(?i)<\s*script\b[^>]*>`)

	pdfHeaderPattern     = []byte("%PDF-")
	pdfJsPattern         = regexp.MustCompile(`(?i)/(?:JavaScript|JS)\b`)
	pdfLaunchPattern     = regexp.MustCompile(`(?i)/Launch\b`)
	pdfOpenActionPattern = regexp.MustCompile(`(?i)/(?:OpenAction|AA)\b`)
	pdfEmbeddedPattern   = regexp.MustCompile(`(?i)/(?:EmbeddedFiles|EF)\b`)
	pdfUriScriptPattern  = regexp.MustCompile(`(?i)/URI\s*\(.*?(?:javascript|data|vbscript):`)

	compressedMediaExtensions = map[string]bool{
		".zip": true, ".gz": true, ".tgz": true, ".tar.gz": true, ".bz2": true, ".xz": true, ".7z": true, ".rar": true,
		".jpg": true, ".jpeg": true, ".png": true, ".webp": true, ".gif": true, ".mp4": true, ".webm": true, ".mov": true,
		".mp3": true, ".ogg": true, ".flac": true, ".docx": true, ".xlsx": true, ".pptx": true,
	}
)

func isExecutableBinary(data []byte) (bool, string) {
	if len(data) < 4 {
		return false, ""
	}
	if bytes.HasPrefix(data, []byte("\x7fELF")) {
		return true, "Linux ELF binary"
	}
	if data[0] == 'M' && data[1] == 'Z' {
		if len(data) >= 64 {
			peOffset := int(binary.LittleEndian.Uint32(data[0x3C:0x40]))
			if peOffset >= 0x40 && peOffset+4 <= len(data) && bytes.Equal(data[peOffset:peOffset+4], []byte("PE\x00\x00")) {
				return true, "Windows PE binary"
			}
		}
		return true, "DOS / Windows executable"
	}
	if len(data) >= 4 {
		magic := binary.BigEndian.Uint32(data[:4])
		magicLE := binary.LittleEndian.Uint32(data[:4])
		if magic == 0xFEEDFACE || magicLE == 0xFEEDFACE || magic == 0xFEEDFACF || magicLE == 0xFEEDFACF {
			return true, "macOS Mach-O binary"
		}
		if magic == 0xCAFEBABE || magicLE == 0xCAFEBABE {
			return true, "Mach-O Fat binary / Java bytecode"
		}
	}
	return false, ""
}

func isServerSideCode(data []byte) (bool, string) {
	if scriptShebangPattern.Match(data) {
		return true, "Server executable script shebang"
	}
	if phpScriptPattern.Match(data) {
		if phpDangerousFuncPattern.Match(data) {
			return true, "PHP web shell execution primitive"
		}
		if phpEvalPattern.Match(data) {
			return true, "PHP dynamic code evaluation"
		}
		return true, "Embedded PHP script"
	}
	if aspServerPattern.Match(data) {
		return true, "ASP.NET server script"
	}
	if jspServerPattern.Match(data) {
		return true, "JSP server script"
	}
	if pythonExecutionPattern.Match(data) {
		return true, "Python process execution payload"
	}
	if nodeExecutionPattern.Match(data) {
		return true, "Node.js child_process server code"
	}
	return false, ""
}

func isMacroDocument(filename string, data []byte) (bool, string) {
	lowerExt := strings.ToLower(filepath.Ext(filename))
	if macroFileExtensions[lowerExt] {
		return true, fmt.Sprintf("Macro-enabled Office document extension (%s)", lowerExt)
	}
	if bytes.HasPrefix(data, zipHeader) && len(data) >= 30 {
		reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err == nil {
			for _, file := range reader.File {
				lowerName := strings.ToLower(file.Name)
				if strings.Contains(lowerName, "vbaproject.bin") {
					return true, fmt.Sprintf("OOXML container with embedded VBA macro (%s)", file.Name)
				}
			}
		}
	}
	if bytes.HasPrefix(data, ole2Header) {
		for _, indicator := range oleMacroIndicators {
			if bytes.Contains(data, indicator) {
				return true, fmt.Sprintf("OLE2 compound document contains embedded VBA (%s)", string(indicator))
			}
		}
	}
	return false, ""
}

func isScriptableSVG(filename string, data []byte) (bool, string) {
	lowerExt := strings.ToLower(filepath.Ext(filename))
	isSVG := lowerExt == ".svg" || lowerExt == ".svgz"
	if !isSVG && len(data) > 0 {
		header := data[:minInt(len(data), 1024)]
		if svgTagPattern.Match(header) || (bytes.Contains(header, []byte("<?xml")) && bytes.Contains(header, []byte("<svg"))) {
			isSVG = true
		}
	}
	if !isSVG {
		return false, ""
	}
	if svgScriptPattern.Match(data) {
		return true, "SVG contains embedded <script> tag"
	}
	if svgEventPattern.Match(data) {
		return true, "SVG contains event handler attribute"
	}
	if svgPseudoPattern.Match(data) {
		return true, "SVG contains javascript/data URI in link attribute"
	}
	if svgForeignObject.Match(data) {
		return true, "SVG contains <foreignObject> container"
	}
	if svgXXEPattern.Match(data) {
		return true, "SVG contains XML External Entity (XXE) definition"
	}
	return false, ""
}

func isDisguisedHTML(filename string, data []byte) (bool, string) {
	lowerExt := strings.ToLower(filepath.Ext(filename))
	if lowerExt == ".html" || lowerExt == ".htm" || lowerExt == ".xhtml" {
		return false, ""
	}
	if htmlDocPattern.Match(data) {
		return true, "HTML document structure disguised under non-HTML extension"
	}
	if htmlFormPattern.Match(data) && htmlPasswordPattern.Match(data) {
		return true, "Phishing login form with password input disguised in upload"
	}
	if htmlRefreshPattern.Match(data) {
		return true, "HTML meta-refresh redirect disguised in upload"
	}
	if htmlIframePattern.Match(data) {
		return true, "HTML iframe element disguised in upload"
	}
	if htmlScriptTagPattern.Match(data) && lowerExt != ".js" && lowerExt != ".ts" && lowerExt != ".json" {
		return true, "HTML <script> tag disguised in non-script file"
	}
	return false, ""
}

func isPDFExploit(filename string, data []byte) (bool, string) {
	lowerExt := strings.ToLower(filepath.Ext(filename))
	isPDF := lowerExt == ".pdf"
	if !isPDF && len(data) >= 4 {
		header := data[:minInt(len(data), 1024)]
		if bytes.Contains(header, pdfHeaderPattern) {
			isPDF = true
		}
	}
	if !isPDF {
		return false, ""
	}
	if pdfJsPattern.Match(data) {
		return true, "Embedded PDF /JavaScript execution"
	}
	if pdfLaunchPattern.Match(data) {
		return true, "Embedded PDF /Launch system process action"
	}
	if pdfOpenActionPattern.Match(data) {
		return true, "Embedded PDF /OpenAction auto-execution trigger"
	}
	if pdfEmbeddedPattern.Match(data) {
		return true, "Embedded binary file dropper (/EmbeddedFiles)"
	}
	if pdfUriScriptPattern.Match(data) {
		return true, "Embedded PDF /URI pseudo-protocol script injection"
	}
	return false, ""
}

func calculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	total := float64(len(data))
	var entropy float64
	for _, count := range counts {
		if count > 0 {
			p := float64(count) / total
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

func isHighEntropyPayload(filename string, data []byte) (bool, string) {
	if len(data) < 256 {
		return false, ""
	}
	lowerExt := strings.ToLower(filepath.Ext(filename))
	isExec, _ := isExecutableBinary(data)
	if !isExec && compressedMediaExtensions[lowerExt] {
		return false, ""
	}
	entropy := calculateEntropy(data)
	if isExec && entropy >= 7.20 {
		return true, fmt.Sprintf("High Shannon entropy in binary (%.2f/8.0) indicating packed/encrypted payload", entropy)
	}
	if !compressedMediaExtensions[lowerExt] && entropy >= 7.35 {
		return true, fmt.Sprintf("High Shannon entropy in non-archive upload (%.2f/8.0) indicating encrypted/obfuscated payload", entropy)
	}
	return false, ""
}

func normalizeUploadMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case string(UploadActionAllow), "off":
		return string(UploadActionAllow)
	case string(UploadActionBlock), "blocking":
		return string(UploadActionBlock)
	default:
		return string(UploadActionDetect)
	}
}

func dominantUploadAction(current, next string) string {
	if current == string(UploadActionBlock) || next == string(UploadActionBlock) {
		return string(UploadActionBlock)
	}
	if current == string(UploadActionDetect) || next == string(UploadActionDetect) {
		return string(UploadActionDetect)
	}
	return string(UploadActionAllow)
}

func safeUploadExcerpt(raw string) string {
	clean := strings.Map(func(r rune) rune {
		if r < 32 && r != '\t' && r != '\n' && r != '\r' {
			return -1
		}
		return r
	}, raw)
	clean = strings.Join(strings.Fields(clean), " ")
	if len(clean) <= 16 {
		return clean
	}
	if len(clean) > 80 {
		clean = clean[:80]
	}
	return clean[:8] + "..." + clean[len(clean)-8:]
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func stringInSlice(needle string, haystack []string) bool {
	needle = strings.ToLower(strings.TrimSpace(needle))
	for _, item := range haystack {
		if strings.ToLower(strings.TrimSpace(item)) == needle {
			return true
		}
	}
	return false
}

func sameMimeFamily(declared, detected string) bool {
	declared = strings.ToLower(strings.TrimSpace(strings.Split(declared, ";")[0]))
	detected = strings.ToLower(strings.TrimSpace(strings.Split(detected, ";")[0]))
	if declared == "" || detected == "" || declared == detected {
		return true
	}
	if declared == "application/octet-stream" {
		return true
	}
	dMajor, _, _ := strings.Cut(declared, "/")
	tMajor, _, _ := strings.Cut(detected, "/")
	return dMajor != "" && dMajor == tMajor
}

func archiveExpansionLimit(archiveSize, maxExpanded int64, maxRatio int) int64 {
	if maxExpanded <= 0 {
		maxExpanded = 100 * 1024 * 1024
	}
	if maxRatio <= 0 {
		maxRatio = 100
	}
	ratioLimit := archiveSize * int64(maxRatio)
	if ratioLimit > 0 && ratioLimit < maxExpanded {
		return ratioLimit
	}
	return maxExpanded
}

func saturatingArchiveSizeAdd(current int64, add uint64) int64 {
	if add > math.MaxInt64 {
		return math.MaxInt64
	}
	if current > math.MaxInt64-int64(add) {
		return math.MaxInt64
	}
	return current + int64(add)
}

func unsafeArchivePath(path string) bool {
	clean := filepath.Clean(path)
	return strings.HasPrefix(clean, "..") || filepath.IsAbs(path) || strings.Contains(path, "../") || strings.Contains(path, `..\`)
}

func isArchiveName(name string) bool {
	lower := strings.ToLower(name)
	for _, ext := range []string{".zip", ".tar", ".tar.gz", ".tgz", ".bz2", ".xz", ".7z", ".rar"} {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

func isExecutableName(name string) bool {
	lower := strings.ToLower(name)
	for _, ext := range []string{".exe", ".dll", ".so", ".dylib", ".sh", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".php", ".phtml", ".jsp", ".asp", ".aspx"} {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}
