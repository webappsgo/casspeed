// Package i18n embeds the shared locale catalog used by every CasSpeed binary.
package i18n

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"sync"

	"golang.org/x/text/feature/plural"
	"golang.org/x/text/language"
)

//go:embed locales/*.json
var localeFS embed.FS

var (
	englishOnce sync.Once
	english     *Catalog
)

type Metadata struct {
	Language         string   `json:"language"`
	Name             string   `json:"name"`
	Native           string   `json:"native_name"`
	Direction        string   `json:"direction"`
	PluralCategories []string `json:"plural_categories"`
	Version          string   `json:"version"`
}

type Catalog struct {
	Meta     Metadata
	Messages map[string]any
}

func Supported() ([]Metadata, error) {
	files, err := fs.Glob(localeFS, "locales/*.json")
	if err != nil {
		return nil, fmt.Errorf("list embedded locales: %w", err)
	}
	result := make([]Metadata, 0, len(files))
	for _, file := range files {
		catalog, err := Load(path.Base(file[:len(file)-len(path.Ext(file))]))
		if err != nil {
			return nil, err
		}
		result = append(result, catalog.Meta)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Language < result[j].Language })
	return result, nil
}

func Load(language string) (*Catalog, error) {
	language = strings.ToLower(strings.TrimSpace(language))
	data, err := localeFS.ReadFile("locales/" + language + ".json")
	if err != nil {
		return nil, fmt.Errorf("read embedded locale %q: %w", language, err)
	}
	var decoded struct {
		Meta     Metadata       `json:"meta"`
		Messages map[string]any `json:"-"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return nil, fmt.Errorf("decode embedded locale %q: %w", language, err)
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("decode embedded locale messages %q: %w", language, err)
	}
	delete(root, "meta")
	decoded.Messages = root
	if decoded.Meta.Language != language || (decoded.Meta.Direction != "ltr" && decoded.Meta.Direction != "rtl") {
		return nil, fmt.Errorf("locale %q has invalid metadata", language)
	}
	return &Catalog{Meta: decoded.Meta, Messages: decoded.Messages}, nil
}

func JSON(language string) ([]byte, error) {
	language = strings.ToLower(strings.TrimSpace(language))
	if _, err := Load(language); err != nil {
		return nil, err
	}
	data, err := localeFS.ReadFile("locales/" + language + ".json")
	if err != nil {
		return nil, fmt.Errorf("read embedded locale %q: %w", language, err)
	}
	return data, nil
}

func Resolve(language string) (*Catalog, error) {
	return Load(Normalize(language))
}

func Normalize(language string) string {
	language = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(language, "_", "-")))
	metadata, err := Supported()
	if err != nil {
		return "en"
	}
	for _, locale := range metadata {
		if language == strings.ToLower(locale.Language) {
			return locale.Language
		}
	}
	base := strings.SplitN(language, "-", 2)[0]
	for _, locale := range metadata {
		if base == strings.ToLower(locale.Language) {
			return locale.Language
		}
	}
	return "en"
}

// IsSupportedTag reports whether a language tag maps to an embedded locale.
func IsSupportedTag(language string) bool {
	language = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(language, "_", "-")))
	metadata, err := Supported()
	if err != nil {
		return false
	}
	base := strings.SplitN(language, "-", 2)[0]
	for _, locale := range metadata {
		code := strings.ToLower(locale.Language)
		if language == code || base == code {
			return true
		}
	}
	return false
}

func (c *Catalog) T(key string, values map[string]string) string {
	message, ok := lookup(c.Messages, key)
	if !ok && c.Meta.Language != "en" {
		englishOnce.Do(func() {
			english, _ = Load("en")
		})
		if english != nil {
			message, ok = lookup(english.Messages, key)
		}
	}
	if !ok {
		return key
	}
	return interpolate(message, values)
}

// Plural selects the locale's CLDR cardinal category and interpolates named values.
func (c *Catalog) Plural(key string, count int, values map[string]string) string {
	value, ok := lookupValue(c.Messages, key)
	if !ok && c.Meta.Language != "en" {
		englishOnce.Do(func() { english, _ = Load("en") })
		if english != nil {
			value, ok = lookupValue(english.Messages, key)
		}
	}
	if !ok {
		return key
	}
	forms, ok := value.(map[string]any)
	if !ok {
		return key
	}
	if count == 0 {
		if text, exists := forms["zero"].(string); exists {
			return interpolate(text, addCount(values, count))
		}
	}
	tag, err := language.Parse(c.Meta.Language)
	if err != nil {
		tag = language.English
	}
	form := plural.Cardinal.MatchPlural(tag, count, 0, 0, 0, 0)
	category := map[plural.Form]string{plural.Zero: "zero", plural.One: "one", plural.Two: "two", plural.Few: "few", plural.Many: "many", plural.Other: "other"}[form]
	text, exists := forms[category].(string)
	if !exists {
		text, exists = forms["other"].(string)
	}
	if !exists {
		return key
	}
	return interpolate(text, addCount(values, count))
}

func addCount(values map[string]string, count int) map[string]string {
	result := make(map[string]string, len(values)+1)
	for key, value := range values {
		result[key] = value
	}
	result["count"] = fmt.Sprint(count)
	return result
}

func interpolate(message string, values map[string]string) string {
	for name, value := range values {
		message = strings.ReplaceAll(message, "{"+name+"}", value)
	}
	return message
}

func lookupValue(messages map[string]any, key string) (any, bool) {
	var current any = messages
	for _, part := range strings.Split(key, ".") {
		group, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = group[part]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func lookup(messages map[string]any, key string) (string, bool) {
	var current any = messages
	for _, part := range strings.Split(key, ".") {
		group, ok := current.(map[string]any)
		if !ok {
			return "", false
		}
		current, ok = group[part]
		if !ok {
			return "", false
		}
	}
	message, ok := current.(string)
	return message, ok
}
