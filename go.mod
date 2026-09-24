module github.com/divinelab-io/aegis

go 1.25.0

require (
	github.com/ClickHouse/clickhouse-go/v2 v2.45.0
	github.com/Microsoft/go-winio v0.6.2
	github.com/alexedwards/scs/redisstore v0.0.0-20251002162104-209de6e426de
	github.com/alexedwards/scs/v2 v2.9.0
	github.com/corazawaf/coraza/v3 v3.3.3
	github.com/dlclark/regexp2 v1.12.0
	github.com/getkin/kin-openapi v0.140.0
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/gomodule/redigo v1.8.0
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.10.0
	github.com/mitchellh/mapstructure v1.5.0
	github.com/oschwald/geoip2-golang v1.13.0
	github.com/pquerna/otp v1.5.0
	github.com/prometheus/client_golang v1.23.2
	github.com/quic-go/quic-go v0.59.0
	github.com/spf13/viper v1.18.2
	github.com/vektah/gqlparser/v2 v2.5.35
	github.com/yl2chen/cidranger v1.0.2
	go.uber.org/zap v1.27.1
	golang.org/x/crypto v0.48.0
	golang.org/x/mod v0.33.0
	golang.org/x/net v0.50.0
	golang.org/x/sync v0.20.0
	golang.org/x/sys v0.42.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/ClickHouse/ch-go v0.71.0 // indirect
	github.com/agnivade/levenshtein v1.2.1 // indirect
	github.com/andybalholm/brotli v1.2.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/corazawaf/libinjection-go v0.2.2 // indirect
	github.com/fsnotify/fsnotify v1.7.0 // indirect
	github.com/go-faster/city v1.0.1 // indirect
	github.com/go-faster/errors v0.7.1 // indirect
	github.com/go-openapi/jsonpointer v0.22.5 // indirect
	github.com/go-openapi/swag/jsonname v0.25.5 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/klauspost/compress v1.18.3 // indirect
	github.com/magefile/mage v1.15.1-0.20241126214340-bdc92f694516 // indirect
	github.com/magiconair/properties v1.8.10 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/oasdiff/yaml v0.1.0 // indirect
	github.com/oasdiff/yaml3 v0.0.13 // indirect
	github.com/oschwald/maxminddb-golang v1.13.0 // indirect
	github.com/paulmach/orb v0.12.0 // indirect
	github.com/pelletier/go-toml/v2 v2.1.0 // indirect
	github.com/petar-dambovaliev/aho-corasick v0.0.0-20240411101913-e07a1f0e8eb4 // indirect
	github.com/pierrec/lz4/v4 v4.1.25 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.66.1 // indirect
	github.com/prometheus/procfs v0.16.1 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/rogpeppe/go-internal v1.12.0 // indirect
	github.com/sagikazarmark/locafero v0.4.0 // indirect
	github.com/sagikazarmark/slog-shim v0.1.0 // indirect
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.2 // indirect
	github.com/segmentio/asm v1.2.1 // indirect
	github.com/shopspring/decimal v1.4.0 // indirect
	github.com/sourcegraph/conc v0.3.0 // indirect
	github.com/spf13/afero v1.11.0 // indirect
	github.com/spf13/cast v1.6.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/tidwall/gjson v1.18.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/valllabh/ocsf-schema-golang v1.0.3 // indirect
	go.opentelemetry.io/otel v1.41.0 // indirect
	go.opentelemetry.io/otel/trace v1.41.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.yaml.in/yaml/v2 v2.4.2 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/exp v0.0.0-20250620022241-b7579e27df2b // indirect
	golang.org/x/text v0.34.0 // indirect
	golang.org/x/tools v0.42.0 // indirect
	google.golang.org/protobuf v1.36.8 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	rsc.io/binaryregexp v0.2.0 // indirect
)

// go.mod.enterprise // // Extra Go dependencies required by the enterprise overlay. // This file is appended to the community go.mod during the enterprise build, // then `go mod tidy` is run to deduplicate and pin versions. // // Format: standard go.mod `require` entries (one per line, no require block needed) // The overlay.sh script appends this after the community go.mod.  require (     github.com/dlclark/regexp2          v1.11.5   // bot detection — advanced regex engine     github.com/getkin/kin-openapi/v0    v0.127.0  // API security — OpenAPI schema validation     github.com/vektah/gqlparser/v2      v2.5.21   // API security — GraphQL parsing     github.com/golang-jwt/jwt/v5        v5.2.2    // licensing — JWT lease tokens     golang.org/x/mod                    v0.22.0   // maintenance — semver parsing )
