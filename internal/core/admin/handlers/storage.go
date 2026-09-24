package handlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/divinelab-io/aegis/internal/infra/config"
	"github.com/divinelab-io/aegis/internal/infra/storage"
)

const maxPostgreSQLPreflightRequestBytes = 16 << 10

type postgreSQLPreflightRequest struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Database string `json:"database"`
	Username string `json:"username"`
	Password string `json:"password"`
	SSLMode  string `json:"ssl_mode"`
}

type postgreSQLPreflightResponse struct {
	Status     string                            `json:"status"`
	Connection storage.PostgreSQLPreflightResult `json:"connection"`
}

type postgreSQLControlPendingRequest struct {
	Host              string `json:"host"`
	Port              int    `json:"port"`
	Database          string `json:"database"`
	Username          string `json:"username"`
	PasswordSecretRef string `json:"password_secret_ref"`
	SSLMode           string `json:"ssl_mode"`
}

type postgreSQLControlPendingResponse struct {
	Status          string `json:"status"`
	RestartRequired bool   `json:"restart_required"`
}

type clickHousePreflightRequest struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Database string `json:"database"`
	Username string `json:"username"`
	Password string `json:"password"`
	Secure   bool   `json:"secure"`
}

type clickHousePreflightResponse struct {
	Status     string                            `json:"status"`
	Connection storage.ClickHousePreflightResult `json:"connection"`
}

type clickHouseAnalyticsPendingRequest struct {
	Mode              storage.AnalyticsMode `json:"mode"`
	Host              string                `json:"host"`
	Port              int                   `json:"port"`
	Database          string                `json:"database"`
	Username          string                `json:"username"`
	PasswordSecretRef string                `json:"password_secret_ref"`
	Secure            bool                  `json:"secure"`
}

type clickHouseAnalyticsPendingResponse struct {
	Status          string `json:"status"`
	RestartRequired bool   `json:"restart_required"`
}

type storageRuntimeStatus struct {
	Driver                string `json:"driver"`
	Configured            bool   `json:"configured"`
	EnvironmentLocked     bool   `json:"environment_locked"`
	Active                bool   `json:"active"`
	Available             bool   `json:"available"`
	Mode                  string `json:"mode,omitempty"`
	RestartRequired       bool   `json:"restart_required"`
	AnalyticsCapabilities string `json:"analytics_capabilities,omitempty"`
}

type storageStatusResponse struct {
	Control   storageRuntimeStatus `json:"control"`
	Analytics storageRuntimeStatus `json:"analytics"`
}

// HandleStorageControlPostgreSQLPreflight validates and tests only the
// submitted, temporary PostgreSQL connection. It never calls configuration
// persistence or storage activation and it deliberately returns opaque errors
// because driver errors can contain credentials or a connection URL.
func (h *Handler) HandleStorageControlPostgreSQLPreflight(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		writePostgreSQLPreflightError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxPostgreSQLPreflightRequestBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request postgreSQLPreflightRequest
	if err := decoder.Decode(&request); err != nil {
		writePostgreSQLPreflightError(w, http.StatusBadRequest, "INVALID_POSTGRESQL_PREFLIGHT_REQUEST")
		return
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		writePostgreSQLPreflightError(w, http.StatusBadRequest, "INVALID_POSTGRESQL_PREFLIGHT_REQUEST")
		return
	}

	preflightConfig := storage.PostgreSQLPreflightConfig{
		Host:     request.Host,
		Port:     request.Port,
		Database: request.Database,
		Username: request.Username,
		Password: request.Password,
		SSLMode:  request.SSLMode,
	}
	if err := preflightConfig.Validate(); err != nil {
		writePostgreSQLPreflightError(w, http.StatusBadRequest, "INVALID_POSTGRESQL_PREFLIGHT_REQUEST")
		return
	}

	runner := h.PostgreSQLPreflight
	if runner == nil {
		runner = storage.NewPostgreSQLPreflightRunner()
	}
	ctx, cancel := context.WithTimeout(r.Context(), storage.PostgreSQLPreflightTimeout)
	defer cancel()
	result, err := runner.Preflight(ctx, preflightConfig)
	if err != nil {
		writePostgreSQLPreflightError(w, http.StatusUnprocessableEntity, "POSTGRESQL_CONNECTION_FAILED")
		return
	}

	_ = json.NewEncoder(w).Encode(postgreSQLPreflightResponse{
		Status:     "ok",
		Connection: result,
	})
}

func writePostgreSQLPreflightError(w http.ResponseWriter, status int, code string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "error",
		"error": map[string]string{
			"code": code,
		},
	})
}

// HandleStorageControlPostgreSQLPending saves only the non-secret PostgreSQL
// connection metadata and an env: secret reference as a pending startup
// configuration. It intentionally does not change the active pool; a restart
// is required for activation.
func (h *Handler) HandleStorageControlPostgreSQLPending(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		writePostgreSQLPreflightError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	if config.ControlDatabaseConfigurationEnvironmentLocked() {
		writePostgreSQLPreflightError(w, http.StatusConflict, "POSTGRESQL_CONTROL_CONFIGURATION_ENVIRONMENT_LOCKED")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxPostgreSQLPreflightRequestBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request postgreSQLControlPendingRequest
	if err := decoder.Decode(&request); err != nil {
		writePostgreSQLPreflightError(w, http.StatusBadRequest, "INVALID_POSTGRESQL_CONTROL_CONFIGURATION")
		return
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		writePostgreSQLPreflightError(w, http.StatusBadRequest, "INVALID_POSTGRESQL_CONTROL_CONFIGURATION")
		return
	}

	next := storage.ControlConfig{
		Enabled:           true,
		Driver:            storage.ControlDriverPostgreSQL,
		Host:              request.Host,
		Port:              request.Port,
		Database:          request.Database,
		Username:          request.Username,
		PasswordSecretRef: request.PasswordSecretRef,
		SSLMode:           request.SSLMode,
	}
	if err := config.UpdateStorageControlConfig(next); err != nil {
		writePostgreSQLPreflightError(w, http.StatusBadRequest, "INVALID_POSTGRESQL_CONTROL_CONFIGURATION")
		return
	}

	_ = json.NewEncoder(w).Encode(postgreSQLControlPendingResponse{
		Status:          "pending",
		RestartRequired: true,
	})
}

// HandleStorageAnalyticsClickHousePreflight tests only the submitted,
// temporary ClickHouse password. It does not create a database, apply schema
// migrations, persist configuration, or change the active runtime.
func (h *Handler) HandleStorageAnalyticsClickHousePreflight(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		writePostgreSQLPreflightError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxPostgreSQLPreflightRequestBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request clickHousePreflightRequest
	if err := decoder.Decode(&request); err != nil {
		writePostgreSQLPreflightError(w, http.StatusBadRequest, "INVALID_CLICKHOUSE_PREFLIGHT_REQUEST")
		return
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		writePostgreSQLPreflightError(w, http.StatusBadRequest, "INVALID_CLICKHOUSE_PREFLIGHT_REQUEST")
		return
	}
	preflightConfig := storage.ClickHousePreflightConfig{
		Host: request.Host, Port: request.Port, Database: request.Database,
		Username: request.Username, Password: request.Password, Secure: request.Secure,
	}
	if err := preflightConfig.Validate(); err != nil {
		writePostgreSQLPreflightError(w, http.StatusBadRequest, "INVALID_CLICKHOUSE_PREFLIGHT_REQUEST")
		return
	}
	runner := h.ClickHousePreflight
	if runner == nil {
		runner = storage.NewClickHousePreflightRunner()
	}
	ctx, cancel := context.WithTimeout(r.Context(), storage.ClickHousePreflightTimeout)
	defer cancel()
	result, err := runner.Preflight(ctx, preflightConfig)
	if err != nil {
		writePostgreSQLPreflightError(w, http.StatusUnprocessableEntity, "CLICKHOUSE_CONNECTION_FAILED")
		return
	}
	_ = json.NewEncoder(w).Encode(clickHousePreflightResponse{Status: "ok", Connection: result})
}

// HandleStorageAnalyticsClickHousePending saves only non-secret ClickHouse
// startup metadata. It deliberately does not restart or hot-swap analytics.
func (h *Handler) HandleStorageAnalyticsClickHousePending(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		writePostgreSQLPreflightError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	if config.AnalyticsDatabaseConfigurationEnvironmentLocked() {
		writePostgreSQLPreflightError(w, http.StatusConflict, "CLICKHOUSE_ANALYTICS_CONFIGURATION_ENVIRONMENT_LOCKED")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxPostgreSQLPreflightRequestBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request clickHouseAnalyticsPendingRequest
	if err := decoder.Decode(&request); err != nil {
		writePostgreSQLPreflightError(w, http.StatusBadRequest, "INVALID_CLICKHOUSE_ANALYTICS_CONFIGURATION")
		return
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		writePostgreSQLPreflightError(w, http.StatusBadRequest, "INVALID_CLICKHOUSE_ANALYTICS_CONFIGURATION")
		return
	}
	next := storage.AnalyticsConfig{
		Mode: request.Mode, Driver: storage.DriverClickHouse, Host: request.Host,
		Port: request.Port, Database: request.Database, Username: request.Username,
		PasswordSecretRef: request.PasswordSecretRef, Secure: request.Secure,
	}
	if err := config.UpdateStorageAnalyticsConfig(next); err != nil {
		writePostgreSQLPreflightError(w, http.StatusBadRequest, "INVALID_CLICKHOUSE_ANALYTICS_CONFIGURATION")
		return
	}
	_ = json.NewEncoder(w).Encode(clickHouseAnalyticsPendingResponse{Status: "pending", RestartRequired: true})
}

// HandleStorageStatus returns an operator-safe view of the active storage
// processes. It deliberately excludes credentials, secret references, driver
// errors, and connection URLs.
func (h *Handler) HandleStorageStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writePostgreSQLPreflightError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	cfg := config.GetGlobalConfig()
	if cfg == nil {
		writePostgreSQLPreflightError(w, http.StatusServiceUnavailable, "STORAGE_STATUS_UNAVAILABLE")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(setupStorageStatusSnapshot(r.Context(), cfg))
}
