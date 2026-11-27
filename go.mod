module github.com/casapps/casspeed

go 1.26.0

require (
	filippo.io/edwards25519 v1.1.0
	github.com/ProtonMail/go-crypto v1.5.2-proton
	// Network/HTTP
	github.com/go-chi/chi/v5 v5.3.0 // Router

	// Utilities
	github.com/go-co-op/gocron/v2 v2.22.0 // Scheduler
	github.com/go-webauthn/webauthn v0.13.4
	github.com/google/uuid v1.6.0 // UUID generation
	github.com/gorilla/websocket v1.5.4-0.20240701034025-d67f41855da4 // WebSocket

	// Core
	github.com/graph-gophers/graphql-go v1.10.3
	github.com/microcosm-cc/bluemonday v1.0.27
	github.com/prometheus/client_golang v1.23.2
	github.com/redis/go-redis/v9 v9.24.0
	github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e
	gopkg.in/yaml.v3 v3.0.1 // YAML config
	// Database drivers
	modernc.org/sqlite v1.34.5 // SQLite (pure Go)
)

require (
	github.com/charmbracelet/bubbletea v1.3.10
	github.com/charmbracelet/lipgloss v1.1.0
	github.com/cretz/bine v0.2.0
	github.com/pires/go-proxyproto v0.10.0
	github.com/prometheus/common v0.66.1
	github.com/yuin/goldmark v1.7.17
	golang.org/x/crypto v0.59.0
	golang.org/x/net v0.63.0
	golang.org/x/sys v0.50.0
	golang.org/x/term v0.48.0
	golang.org/x/text v0.44.0
)

require (
	github.com/aymanbagabas/go-osc52/v2 v2.0.1 // indirect
	github.com/aymerick/douceur v0.2.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/charmbracelet/colorprofile v0.2.3-0.20250311203215-f60798e515dc // indirect
	github.com/charmbracelet/x/ansi v0.10.1 // indirect
	github.com/charmbracelet/x/cellbuf v0.0.13-0.20250311204145-2c3ea96c31dd // indirect
	github.com/charmbracelet/x/term v0.2.1 // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/erikgeiser/coninput v0.0.0-20211004153227-1c3628e74d0f // indirect
	github.com/fxamacker/cbor/v2 v2.9.0 // indirect
	github.com/go-webauthn/x v0.1.23 // indirect
	github.com/golang-jwt/jwt/v5 v5.2.3 // indirect
	github.com/google/go-tpm v0.9.5 // indirect
	github.com/gorilla/css v1.0.1 // indirect
	github.com/jonboulle/clockwork v0.5.0 // indirect
	github.com/lucasb-eyer/go-colorful v1.2.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-localereader v0.0.1 // indirect
	github.com/mattn/go-runewidth v0.0.16 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/muesli/ansi v0.0.0-20230316100256-276c6243b2f6 // indirect
	github.com/muesli/cancelreader v0.2.2 // indirect
	github.com/muesli/termenv v0.16.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/ncruces/go-strftime v0.1.9 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/procfs v0.16.1 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/robfig/cron/v3 v3.0.1 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e // indirect
	go.uber.org/atomic v1.12.0 // indirect
	go.yaml.in/yaml/v2 v2.4.2 // indirect
	golang.org/x/crypto/openpgp v0.1.0-deprecated // indirect
	google.golang.org/protobuf v1.36.8 // indirect
	modernc.org/libc v1.55.3 // indirect
	modernc.org/mathutil v1.6.0 // indirect
	modernc.org/memory v1.8.0 // indirect
)
