# Feature Rules (PART 18-23)

⚠️ **These rules are NON-NEGOTIABLE. Violations are bugs.** ⚠️

## CRITICAL - NEVER DO

- Never leave mandatory background, notification, metrics, backup, or update features as stubs.
- Never expose internal-only metrics publicly.

## CRITICAL - ALWAYS DO

- Implement notification, scheduler, GeoIP, metrics, backup/restore, and update requirements.
- Make scheduled work safe, observable, and consistent with configured retention.

## Key rules

- Keep these features configurable and document their operational behavior.

For complete details, see AI.md PART 18, 19, 20, 21, 22, 23.
