# Configuration Rules (PART 5, 6, 12)

⚠️ **These rules are NON-NEGOTIABLE. Violations are bugs.** ⚠️

## CRITICAL - NEVER DO

- Never ignore unknown configuration keys or allow invalid values silently.
- Never enable debug endpoints merely because development mode is active.

## CRITICAL - ALWAYS DO

- Apply configuration precedence and validation exactly as specified.
- Use documented server configuration names and safe defaults.

## Key rules

- Keep production, development, and debug modes distinct; redact credentials in every mode.

For complete details, see AI.md PART 5, 6, 12.
