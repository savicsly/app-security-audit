# Releasing

1. Change the skill files under `skills/app-security-audit/`.
2. Raise the version in both `package.json` and `.claude-plugin/plugin.json`; Claude Code uses the plugin version to detect updates.
3. Check: `node bin/cli.js targets`, `claude plugin validate .`, `npm pack --dry-run`.
4. Commit on a branch, open a PR and merge it into `main` (the Skills CLI and Claude Code plugin read from GitHub). Wait for the CodeRabbit review to finish before merging; closing the PR cancels it.
5. Publish to npm from the merge commit. Record its SHA and confirm `package.json` there declares the version you mean to release:

   ```bash
   git checkout main && git pull
   SHA=$(git rev-parse HEAD)                  # the merge commit
   git show "$SHA:package.json" | grep '"version"'   # must show X.Y.Z
   npm publish
   npm view app-security-audit version        # should print X.Y.Z
   ```

   npm asks for browser or 2FA confirmation, so run `npm publish` in your own terminal.
6. Tag that same commit and create a GitHub release, otherwise the repository's sidebar keeps showing the previous version as Latest. First write the release notes for users of the skill to a file outside the repository (for example `/tmp/release-notes.md`): what's new, then the upgrade command for npm, the Claude Code plugin and the Skills CLI. Then:

   ```bash
   git tag -a vX.Y.Z "$SHA" -m "vX.Y.Z" && git push origin vX.Y.Z
   gh release create vX.Y.Z --title "vX.Y.Z" --latest --notes-file /tmp/release-notes.md
   ```

Keep the installer dependency-free and never add install scripts: people trust this package with their code.
