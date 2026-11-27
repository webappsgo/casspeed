package i18n

import (
	"encoding/json"
	"io/fs"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func TestLocalesFS(t *testing.T) {
	files, err := fs.Glob(localeFS, "locales/*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 6 {
		t.Fatalf("locale count = %d, want at least six", len(files))
	}
	required := map[string][]string{
		"en": {"one", "other"},
		"es": {"one", "other"},
		"fr": {"one", "other"},
		"de": {"one", "other"},
		"it": {"one", "many", "other"},
		"ar": {"zero", "one", "two", "few", "many", "other"},
	}
	for _, file := range files {
		language := strings.TrimSuffix(strings.TrimPrefix(file, "locales/"), ".json")
		catalog, err := Load(language)
		if err != nil {
			t.Fatalf("Load(%q): %v", language, err)
		}
		if catalog.Meta.Name == "" || catalog.Meta.Native == "" || catalog.Meta.Version == "" || len(catalog.Meta.PluralCategories) == 0 {
			t.Errorf("locale %q has incomplete metadata: %#v", language, catalog.Meta)
		}
		if categories, ok := required[language]; ok && !reflect.DeepEqual(catalog.Meta.PluralCategories, categories) {
			t.Errorf("locale %q plural categories = %v, want %v", language, catalog.Meta.PluralCategories, categories)
		}
	}
	for language := range required {
		if _, err := Load(language); err != nil {
			t.Errorf("required locale %q is missing: %v", language, err)
		}
	}
}

func TestKeyConsistency(t *testing.T) {
	base, err := Load("en")
	if err != nil {
		t.Fatal(err)
	}
	want := messageKeys(base.Messages, "")
	for _, metadata := range mustSupported(t) {
		catalog, err := Load(metadata.Language)
		if err != nil {
			t.Fatal(err)
		}
		got := messageKeys(catalog.Messages, "")
		if !reflect.DeepEqual(want, got) {
			t.Errorf("locale %q message keys differ: missing=%v extra=%v", metadata.Language, difference(want, got), difference(got, want))
		}
		validateMessages(t, metadata.Language, catalog.Messages, metadata.PluralCategories)
		for key := range want {
			baseValue, _ := lookupValue(base.Messages, key)
			localeValue, _ := lookupValue(catalog.Messages, key)
			if !reflect.DeepEqual(placeholders(baseValue), placeholders(localeValue)) {
				t.Errorf("locale %q interpolation placeholders differ at %s", metadata.Language, key)
			}
		}
	}
}

func placeholders(value any) map[string]struct{} {
	result := make(map[string]struct{})
	add := func(text string) {
		for _, match := range placeholderPattern.FindAllStringSubmatch(text, -1) {
			if match[1] != "count" {
				result[match[1]] = struct{}{}
			}
		}
	}
	if text, ok := value.(string); ok {
		add(text)
		return result
	}
	if forms, ok := value.(map[string]any); ok {
		for _, raw := range forms {
			if text, ok := raw.(string); ok {
				add(text)
			}
		}
	}
	return result
}

func messageKeys(value map[string]any, prefix string) map[string]struct{} {
	keys := make(map[string]struct{})
	for name, child := range value {
		key := name
		if prefix != "" {
			key = prefix + "." + name
		}
		switch item := child.(type) {
		case map[string]any:
			if isPluralObject(item) {
				keys[key] = struct{}{}
			} else {
				for nested := range messageKeys(item, key) {
					keys[nested] = struct{}{}
				}
			}
		case string:
			keys[key] = struct{}{}
		}
	}
	return keys
}

var placeholderPattern = regexp.MustCompile(`\{([a-zA-Z_][a-zA-Z0-9_]*)\}`)

func isPluralObject(value map[string]any) bool {
	if len(value) == 0 {
		return false
	}
	for key, item := range value {
		if _, ok := item.(string); !ok {
			return false
		}
		switch key {
		case "zero", "one", "two", "few", "many", "other":
		default:
			return false
		}
	}
	return true
}

func validateMessages(t *testing.T, language string, messages map[string]any, requiredCategories []string) {
	t.Helper()
	var visit func(map[string]any, string)
	visit = func(group map[string]any, prefix string) {
		for name, value := range group {
			key := name
			if prefix != "" {
				key = prefix + "." + name
			}
			switch item := value.(type) {
			case string:
				if item == "" {
					t.Errorf("locale %q has empty message at %s", language, key)
				}
			case map[string]any:
				if !isPluralObject(item) {
					visit(item, key)
					continue
				}
				allowed := make(map[string]bool)
				for _, category := range requiredCategories {
					allowed[category] = true
				}
				allowed["zero"] = true
				var placeholders map[string]bool
				for category, raw := range item {
					if !allowed[category] {
						t.Errorf("locale %q plural %s has orphan category %s", language, key, category)
					}
					text := raw.(string)
					if text == "" {
						t.Errorf("locale %q has empty plural message at %s.%s", language, key, category)
					}
					current := make(map[string]bool)
					for _, found := range placeholderPattern.FindAllStringSubmatch(text, -1) {
						if found[1] != "count" {
							current[found[1]] = true
						}
					}
					if placeholders == nil {
						placeholders = current
					} else if !reflect.DeepEqual(placeholders, current) {
						t.Errorf("locale %q plural %s placeholders differ at %s", language, key, category)
					}
				}
				for _, category := range requiredCategories {
					if _, ok := item[category]; !ok {
						t.Errorf("locale %q plural %s lacks category %s", language, key, category)
					}
				}
			}
		}
	}
	visit(messages, "")
}

func difference(left, right map[string]struct{}) []string {
	var missing []string
	for key := range left {
		if _, exists := right[key]; !exists {
			missing = append(missing, key)
		}
	}
	return missing
}

func mustSupported(t *testing.T) []Metadata {
	t.Helper()
	languages, err := Supported()
	if err != nil {
		t.Fatal(err)
	}
	return languages
}

func TestCatalogTranslationAndMetadata(t *testing.T) {
	data, err := JSON("en")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	catalog, err := Resolve("unsupported")
	if err != nil {
		t.Fatal(err)
	}
	if got := catalog.T("common.save", nil); got != "Save" {
		t.Fatalf("fallback translation = %q", got)
	}
}

func TestCatalogPluralForms(t *testing.T) {
	english, err := Load("en")
	if err != nil {
		t.Fatal(err)
	}
	if got := english.Plural("time.minutes_ago", 1, nil); got != "1 minute ago" {
		t.Fatalf("English singular = %q", got)
	}
	if got := english.Plural("time.minutes_ago", 4, nil); got != "4 minutes ago" {
		t.Fatalf("English plural = %q", got)
	}
	arabic, err := Load("ar")
	if err != nil {
		t.Fatal(err)
	}
	if got := arabic.Plural("time.minutes_ago", 2, nil); got != "قبل دقيقتين" {
		t.Fatalf("Arabic dual = %q", got)
	}
}
