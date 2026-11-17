# Releasing

1. Change the skill files under `skills/app-security-audit/`.
2. Raise the version in both `package.json` and `.claude-plugin/plugin.json`; Claude Code uses the plugin version to detect updates.
3. Check: `node bin/cli.js targets`, `claude plugin validate .`, `npm pack --dry-run`.
4. Commit and push to `main` (the Skills CLI and Claude Code plugin read from GitHub), then `npm publish`.

Keep the installer dependency-free and never add install scripts: people trust this package with their code.
