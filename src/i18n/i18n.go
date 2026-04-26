package i18n

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Config holds i18n configuration
type Config struct {
	Enabled         bool
	DefaultLanguage string
	SupportedLangs  []string
	TranslationsDir string
}

// Translation represents a translation map
type Translation map[string]string

// Service manages internationalization
type Service struct {
	config       *Config
	translations map[string]Translation
	mu           sync.RWMutex
}

var (
	instance *Service
	once     sync.Once
)

// GetService returns singleton i18n service instance
func GetService() *Service {
	once.Do(func() {
		instance = &Service{
			translations: make(map[string]Translation),
		}
	})
	return instance
}

// Initialize sets up i18n service with configuration
func (s *Service) Initialize(cfg *Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.config = cfg

	if !cfg.Enabled {
		return nil
	}

	// Load all translations
	for _, lang := range cfg.SupportedLangs {
		if err := s.loadTranslation(lang); err != nil {
			return fmt.Errorf("loading %s translations: %w", lang, err)
		}
	}

	return nil
}

// IsEnabled returns whether i18n is enabled
func (s *Service) IsEnabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config != nil && s.config.Enabled
}

// T translates a key to the specified language
func (s *Service) T(lang, key string, args ...interface{}) string {
	if !s.IsEnabled() {
		return key
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	// Get translation for language
	trans, exists := s.translations[lang]
	if !exists {
		// Fall back to default language
		trans, exists = s.translations[s.config.DefaultLanguage]
		if !exists {
			return key
		}
	}

	// Get translated string
	text, exists := trans[key]
	if !exists {
		return key
	}

	// Replace arguments if provided
	if len(args) > 0 {
		return fmt.Sprintf(text, args...)
	}

	return text
}

// GetSupportedLanguages returns list of supported languages
func (s *Service) GetSupportedLanguages() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.config == nil {
		return []string{"en"}
	}

	return s.config.SupportedLangs
}

// GetDefaultLanguage returns the default language
func (s *Service) GetDefaultLanguage() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.config == nil {
		return "en"
	}

	return s.config.DefaultLanguage
}

// loadTranslation loads translations for a language from file
func (s *Service) loadTranslation(lang string) error {
	translationFile := filepath.Join(s.config.TranslationsDir, fmt.Sprintf("%s.json", lang))

	// Check if file exists
	if _, err := os.Stat(translationFile); os.IsNotExist(err) {
		// Load embedded defaults
		s.translations[lang] = getDefaultTranslations(lang)
		return nil
	}

	data, err := os.ReadFile(translationFile)
	if err != nil {
		return err
	}

	var trans Translation
	if err := json.Unmarshal(data, &trans); err != nil {
		return err
	}

	s.translations[lang] = trans
	return nil
}

// getDefaultTranslations returns embedded default translations
func getDefaultTranslations(lang string) Translation {
	switch lang {
	case "en":
		return Translation{
			"app.name":                "casspeed",
			"app.tagline":             "Self-hosted speed test server",
			"nav.home":                "Home",
			"nav.admin":               "Admin",
			"nav.docs":                "Docs",
			"test.start":              "Start Test",
			"test.running":            "Running...",
			"test.complete":           "Test Complete",
			"test.download":           "Download",
			"test.upload":             "Upload",
			"test.ping":               "Ping",
			"results.share":           "Share Results",
			"results.history":         "Test History",
			"error.generic":           "An error occurred",
			"error.network":           "Network error",
			"admin.dashboard":         "Dashboard",
			"admin.settings":          "Settings",
			"admin.users":             "Users",
			"settings.general":        "General Settings",
			"settings.save":           "Save Changes",
			"login.title":             "Login",
			"login.username":          "Username",
			"login.password":          "Password",
			"login.submit":            "Login",
		}
	case "es":
		return Translation{
			"app.name":                "casspeed",
			"app.tagline":             "Servidor de prueba de velocidad autohospedado",
			"nav.home":                "Inicio",
			"nav.admin":               "Admin",
			"nav.docs":                "Documentos",
			"test.start":              "Iniciar Prueba",
			"test.running":            "Ejecutando...",
			"test.complete":           "Prueba Completada",
			"test.download":           "Descarga",
			"test.upload":             "Subida",
			"test.ping":               "Ping",
			"results.share":           "Compartir Resultados",
			"results.history":         "Historial de Pruebas",
			"error.generic":           "Ocurrió un error",
			"error.network":           "Error de red",
			"admin.dashboard":         "Panel de Control",
			"admin.settings":          "Configuración",
			"admin.users":             "Usuarios",
			"settings.general":        "Configuración General",
			"settings.save":           "Guardar Cambios",
			"login.title":             "Iniciar Sesión",
			"login.username":          "Nombre de Usuario",
			"login.password":          "Contraseña",
			"login.submit":            "Entrar",
		}
	case "fr":
		return Translation{
			"app.name":                "casspeed",
			"app.tagline":             "Serveur de test de vitesse auto-hébergé",
			"nav.home":                "Accueil",
			"nav.admin":               "Admin",
			"nav.docs":                "Documentation",
			"test.start":              "Démarrer le Test",
			"test.running":            "En cours...",
			"test.complete":           "Test Terminé",
			"test.download":           "Téléchargement",
			"test.upload":             "Envoi",
			"test.ping":               "Ping",
			"results.share":           "Partager les Résultats",
			"results.history":         "Historique des Tests",
			"error.generic":           "Une erreur s'est produite",
			"error.network":           "Erreur réseau",
			"admin.dashboard":         "Tableau de Bord",
			"admin.settings":          "Paramètres",
			"admin.users":             "Utilisateurs",
			"settings.general":        "Paramètres Généraux",
			"settings.save":           "Enregistrer les Modifications",
			"login.title":             "Connexion",
			"login.username":          "Nom d'utilisateur",
			"login.password":          "Mot de passe",
			"login.submit":            "Se Connecter",
		}
	default:
		return Translation{}
	}
}

// DetectLanguage detects language from Accept-Language header
func DetectLanguage(acceptLang string) string {
	if acceptLang == "" {
		return "en"
	}

	// Parse Accept-Language header
	langs := strings.Split(acceptLang, ",")
	if len(langs) == 0 {
		return "en"
	}

	// Get first language (highest priority)
	lang := strings.TrimSpace(langs[0])
	lang = strings.Split(lang, ";")[0]
	lang = strings.ToLower(lang)

	// Extract language code (e.g., "en-US" -> "en")
	if len(lang) > 2 {
		lang = lang[:2]
	}

	return lang
}

// FormatNumber formats a number according to locale
func FormatNumber(lang string, value float64) string {
	// Simplified formatting - real implementation would use proper locale formatting
	switch lang {
	case "fr", "de", "es":
		return fmt.Sprintf("%.2f", value)
	default:
		return fmt.Sprintf("%.2f", value)
	}
}

// FormatDate formats a date according to locale
func FormatDate(lang, date string) string {
	// Simplified - real implementation would parse and format according to locale
	return date
}
