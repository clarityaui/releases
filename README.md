# Clarity AUI release controller

This public repository is the release trust boundary for the private
[`clarityaui/main`](https://github.com/clarityaui/main) source repository. It contains no
application source.

## Security model

- `main` is protected. Release workflow changes must arrive through a pull request.
- Pull requests must pass the `Release policy` controller self-test.
- A candidate names one full, immutable source commit SHA and one matching version tag.
- The private source is downloaded with a read-only token in a step that runs before any
  source-controlled command. The credential is not passed to install, test, or build steps.
- Build jobs receive no GitHub or publishing credential.
- A separate job, on a fresh runner, validates the artifact set and creates a draft release.
- A separate workflow invocation validates the draft again before publishing it.
- `internal-unsigned` is an explicitly untrusted test channel. It never claims Windows or
  macOS signing.
- `public-beta` fails closed unless Windows signing and macOS signing/notarization complete.

## Environments and configuration

Create these environments:

| Environment | Purpose | Secrets |
| --- | --- | --- |
| `source-read` | Internal unsigned candidates | `SOURCE_REPO_TOKEN` |
| `beta-signing` | Signed public candidates | `SOURCE_REPO_TOKEN`, Windows and Apple signing credentials |
| `internal-beta` | Final acknowledgement for publishing an unsigned prerelease | none |
| `public-beta` | Independent approval for public promotion | none |

Repository variables:

- `VITE_SUPABASE_URL`
- `VITE_SUPABASE_ANON_KEY`

`SOURCE_REPO_TOKEN` must be a fine-grained token restricted to `clarityaui/main` with only
**Contents: read**. It is deliberately separate from every publishing identity.

## Release procedure

1. Review the exact source commit and copy its full 40-character SHA.
2. Run **Build release candidate** with the tag, SHA, channel, and `BUILD <tag>` acknowledgement.
3. Inspect all green build jobs and the resulting draft release.
4. Run **Promote release candidate** using the same tag, SHA, and channel, and enter
   `PROMOTE <tag>`.
5. For `public-beta`, the protected environment must be approved independently.

Until platform signing identities exist, use only `internal-unsigned` and keep distribution
limited to informed testers.

## Legs

A candidate is six installers, one per leg of the build matrix, and the draft is created only
when all six verified:

| id | runner | target | installer |
| --- | --- | --- | --- |
| `windows-x64` | `windows-latest` | `--win --x64` | `clarity-aui-<v>-x64.exe` |
| `windows-arm64` | `windows-11-arm` | `--win --arm64` | `clarity-aui-<v>-arm64.exe` |
| `macos-arm64` | `macos-latest` | `--mac --arm64` | `clarity-aui-<v>-arm64.dmg` |
| `macos-x64` | `macos-15-intel` | `--mac --x64` | `clarity-aui-<v>-x64.dmg` |
| `linux-x64` | `ubuntu-latest` | `--linux --x64` | `clarity-aui-<v>-x86_64.AppImage` |
| `linux-arm64` | `ubuntu-24.04-arm` | `--linux --arm64` | `clarity-aui-<v>-arm64.AppImage` |

The manifest names each platform by `id`, and carries `family` and `arch` beside it; the
installer's file name carries the arch electron-builder wrote, and the manifest scripts match
on that rather than on the extension, because two legs share every extension. `public-beta`
requires every Windows and macOS leg to be signed; Linux legs are never signed. The two macOS
legs bill at the macOS rate, so the matrix does not fail fast: one red leg does not cancel the
other five and cost a second attempt to learn what they would have said.
