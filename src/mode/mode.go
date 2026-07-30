package mode

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/casapps/casspeed/src/config"
)

// Mode represents application operational mode
type Mode string

const (
	Production  Mode = "production"
	Development Mode = "development"
)

// State represents the application's operational state
type State struct {
	Mode  Mode
	Debug bool
}

// Detect determines mode and debug from CLI flags and environment
// Priority: CLI flag > Environment variable > Default
func Detect(modeFlag, debugFlag string) (*State, error) {
	state := &State{
		Mode:  Production, // Default
		Debug: false,      // Default
	}

	// Determine mode
	mode := modeFlag
	if mode == "" {
		mode = os.Getenv("MODE")
	}
	if mode == "" {
		mode = "production" // Default
	}

	// Normalize mode (support shortcuts)
	mode = strings.ToLower(strings.TrimSpace(mode))
	switch mode {
	case "prod", "production":
		state.Mode = Production
	case "dev", "development":
		state.Mode = Development
	default:
		return nil, fmt.Errorf("invalid mode: %s (must be 'production' or 'development')", mode)
	}

	// Determine debug
	if debugFlag != "" {
		debug, err := config.ParseBool(debugFlag, false)
		if err != nil {
			return nil, fmt.Errorf("invalid debug flag: %w", err)
		}
		state.Debug = debug
	} else {
		debugEnv := os.Getenv("DEBUG")
		if debugEnv != "" {
			debug, err := config.ParseBool(debugEnv, false)
			if err != nil {
				return nil, fmt.Errorf("invalid DEBUG environment variable: %w", err)
			}
			state.Debug = debug
		}
	}

	// Apply runtime profiling rates based on debug flag (PART 6)
	if state.Debug {
		runtime.SetBlockProfileRate(1)
		runtime.SetMutexProfileFraction(1)
	} else {
		runtime.SetBlockProfileRate(0)
		runtime.SetMutexProfileFraction(0)
	}

	return state, nil
}

// String returns a human-readable state description
func (s *State) String() string {
	modeStr := string(s.Mode)
	if s.Debug {
		return fmt.Sprintf("%s [debugging]", modeStr)
	}
	return modeStr
}

// IsProduction returns true if mode is production
func (s *State) IsProduction() bool {
	return s.Mode == Production
}

// IsDevelopment returns true if mode is development
func (s *State) IsDevelopment() bool {
	return s.Mode == Development
}

// IsDebug returns true if debug is enabled
func (s *State) IsDebug() bool {
	return s.Debug
}

// LogLevel returns appropriate log level for the mode
func (s *State) LogLevel() string {
	if s.Debug {
		return "trace" // Most verbose
	}
	if s.IsDevelopment() {
		return "debug"
	}
	return "info"
}

// ShouldCacheTemplates returns true if templates should be cached
func (s *State) ShouldCacheTemplates() bool {
	return s.IsProduction() && !s.Debug
}

// ShouldCacheStatic returns true if static files should be cached
func (s *State) ShouldCacheStatic() bool {
	return s.IsProduction() && !s.Debug
}

// ShouldEnforceRateLimit returns true if rate limiting should be enforced
func (s *State) ShouldEnforceRateLimit() bool {
	return s.IsProduction()
}

// ShouldShowStackTraces returns true if stack traces should be shown in errors
func (s *State) ShouldShowStackTraces() bool {
	return s.IsDevelopment() || s.Debug
}

// ShouldEnableDebugEndpoints returns true if /debug/* endpoints should be enabled
func (s *State) ShouldEnableDebugEndpoints() bool {
	return s.Debug
}

// ShouldEnablePprof returns true if pprof endpoints should be enabled
func (s *State) ShouldEnablePprof() bool {
	return s.Debug
}

// ShouldVerboseLog returns true for verbose request logging
func (s *State) ShouldVerboseLog() bool {
	return s.IsDevelopment() || s.Debug
}

// GetConsoleIcon returns appropriate emoji for console output
func (s *State) GetConsoleIcon() string {
	if s.Debug {
		if s.IsProduction() {
			return "🔒🔧" // Production + Debug (unusual)
		}
		return "🔧" // Development + Debug
	}
	if s.IsProduction() {
		return "🔒" // Production
	}
	return "💻" // Development
}

// PrintStartupMessage prints mode information to console
func (s *State) PrintStartupMessage() {
	icon := s.GetConsoleIcon()
	fmt.Printf("%s Running in mode: %s\n", icon, s.String())

	if s.Debug {
		fmt.Println("⚠️  DEBUG MODE ENABLED:")
		fmt.Println("   - Debug endpoints: /debug/*")
		fmt.Println("   - Profiling: /debug/pprof/*")
		fmt.Println("   - Metrics: /debug/vars")
		fmt.Println("   - Verbose logging enabled")
		if s.IsProduction() {
			fmt.Println("   ⚠️  WARNING: Debug enabled in production!")
		}
	}
}
