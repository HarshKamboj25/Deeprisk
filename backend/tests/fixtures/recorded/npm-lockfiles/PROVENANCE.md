# Real npm lockfile fixtures

Real `package-lock.json` files produced by npm, used to test DepRisk's parser and dependency graph against real data. The lockfiles are npm output, copied byte for byte and never edited. The `package.json` files are hand-written inputs.

## How they were generated

- Machine: Windows (Microsoft Windows NT 10.0.26300.0), Node.js v24.19.0, npm 12.0.2, registry https://registry.npmjs.org/
- DepRisk commit when copied into the repository: 0478f13
- Run in each project directory, from PowerShell in VS Code:
  `npm install --package-lock-only --ignore-scripts --no-audit --no-fund`
  (`general-v2` additionally passes `--lockfile-version 2`.)
- Nothing was installed and no lifecycle scripts ran.

## Projects

| Project | lockfileVersion | Generated | Purpose |
|---|---|---|---|
| general-v3 | 3 | 2026-10-21 12:04 UTC | Direct, dev, optional, scoped and aliased dependencies (`myalias` installs lodash). |
| general-v2 | 2 | 2026-10-21 12:04 UTC | The same package.json as general-v3, written as lockfile v2 (adds the legacy dependencies map). |
| peer-v3 | 3 | 2026-10-21 12:04 UTC | React, react-dom and ESLint plugins: peer dependencies and `peerDependenciesMeta`. |
| flags-v3 | 3 | 2026-10-21 12:05 UTC | Built to produce `devOptional` and `peer` flags (braces is both a dev and an optional-path dependency). |
| workspace-v3 | 3 | 2026-10-21 12:05 UTC | npm workspaces: `link` entries and workspace-member install paths. |

`workspace-v3` also contains its two workspace members' `package.json` files under `packages/`. DepRisk's parser currently rejects its `link` entries on purpose. Its test pins that behaviour until workspace support is designed.

## Integrity

`SHA256SUMS.txt` lists the SHA-256 of every fixture file in this directory (not of itself or of this document). `.gitattributes` marks this directory `-text`, so git never changes line endings and the hashes stay valid on every platform.

Windows, from this directory:

    foreach ($line in Get-Content SHA256SUMS.txt) {
      $hash, $path = $line -split '  ', 2
      $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath ($path -replace '/', '\')).Hash.ToLower()
      '{0,-9} {1}' -f $(if ($actual -eq $hash) { 'OK' } else { 'MISMATCH' }), $path
    }

Linux or macOS: `sha256sum -c SHA256SUMS.txt`

## Limits

- Transitive versions were resolved from the registry on the generation date. Regenerating later can produce different lockfiles, so treat these files as fixed evidence and do not regenerate them casually.
- Tests must assert structural properties of these files, not exact package counts.
- The files contain public registry URLs and integrity hashes and no credentials.
- They show how npm 12.0.2 wrote lockfiles for these five projects on this machine. They are not a survey of other npm versions or project shapes.