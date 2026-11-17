# Releasing

1. Change the skill files under `skills/app-security-audit/`.
2. Raise the version in both `package.json` and `.claude-plugin/plugin.json`; Claude Code uses the plugin version to detect updates.
3. Check: `node bin/cli.js targets`, `claude plugin validate .`, `npm pack --dry-run`.
4. Commit on a branch, open a PR and merge it into `main` (the Skills CLI and Claude Code plugin read from GitHub). Wait for the CodeRabbit review to finish before merging; closing the PR cancels it.
5. Publish to npm from an up-to-date `main`: `git checkout main && git pull`, then `npm publish`. npm asks for browser or 2FA confirmation, so run it in your own terminal. Check with `npm view app-security-audit version`.
6. Tag the merge commit and create a GitHub release, otherwise the repository's sidebar keeps showing the previous version as Latest:

   ```bash
   git tag -a vX.Y.Z -m "vX.Y.Z" && git push origin vX.Y.Z
   gh release create vX.Y.Z --title "vX.Y.Z" --latest --notes "What changed and how to upgrade"
   ```

   Write the release notes for users of the skill: what's new, then the upgrade command for npm, the Claude Code plugin and the Skills CLI.

Keep the installer dependency-free and never add install scripts: people trust this package with their code.
