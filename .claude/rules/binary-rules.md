# Binary Rules (PART 7, 8, 33)

⚠️ **These rules are NON-NEGOTIABLE. Violations are bugs.** ⚠️

## CRITICAL - NEVER DO

- Never require runtime dependencies beyond those explicitly allowed by AI.md.
- Never remove, rename, or change required CLI flags and commands.

## CRITICAL - ALWAYS DO

- Build static binaries with CGO_ENABLED=0 for all required platforms.
- Provide the required client binary and complete its noninteractive and TUI behavior.

## Key rules

- Embed required assets and honor terminal, color, language, and signal behavior.

For complete details, see AI.md PART 7, 8, 33.
