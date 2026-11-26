# Translating CasSpeed

CasSpeed ships English, Spanish, French, German, Italian, and Arabic interface catalogs. English (`en.json`) is the source catalog. Translation files are embedded in the server and CLI binaries.

## Contributing a translation

1. Copy `src/common/i18n/locales/en.json` to `src/common/i18n/locales/{language-code}.json` using the lowercase BCP 47 language code, such as `pt` or `pt-br`.
2. Translate every value and complete the catalog's `meta` fields: language code, English name, native name, text direction, and catalog version. Add a translator name or handle only with that contributor's consent.
3. Keep all keys and their order unchanged. Do not translate keys, product names, protocol names, code, filenames, configuration keys, URLs, or literal option values such as `dark` and `auto`.
4. Preserve every `{placeholder}` exactly, including its spelling and braces. A placeholder may move within a sentence when the language requires a different word order.
5. Supply every CLDR plural category required by the language. Do not combine sentence fragments; each value must be a complete phrase.
6. Register the locale and its text direction and plural categories as required by the catalog registry and server configuration.
7. Update the supported-language list here and in the README whenever a locale is added or retired. Keep translator credits here and in the locale's metadata.
8. Run the project test gate with `make test` and review the interface at 320, 768, and 1280 pixels. Check longer text for clipping and overflow; verify right-to-left layout in Arabic and any other RTL locale.

## Translation style

Use a consistent, neutral register and the same translation for recurring product terms. Keep technical identifiers in their original form. Follow the locale's punctuation, quotation, decimal, and thousands-separator conventions. The application formats numbers and dates; do not insert locale-specific punctuation into format placeholders.

| English term | Meaning in CasSpeed | Translation guidance |
|---|---|---|
| Test | One connection measurement run | Use the same term for the action and its history entry |
| Result | Measurements and metadata produced by a test | Distinguish a result from a share link |
| Share | An explicitly created public link to a result | Keep the opt-in/public meaning clear |
| Device | A named client associated with a user's account | Do not translate as physical server equipment |
| Token | A bearer credential used by an API client | Keep API and token terminology consistent |
| Revoke | Permanently invalidate a token or session | Distinguish from signing out |

The current supported languages are English (`en`), Spanish (`es`), French (`fr`), German (`de`), Italian (`it`), and Arabic (`ar`). See each locale file's `meta` block for translator credits. No individual translator is credited until they opt in.

## Validation

The test suite checks that each catalog has the same keys as English, values are non-empty, interpolation placeholders match, and each locale includes its required plural categories. Run it inside the project's Go toolchain container through `make test`; do not run Go tools directly on the host.
