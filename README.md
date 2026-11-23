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

## Update feeds

electron-updater reads four feeds: `latest.yml` (Windows), `latest-mac.yml`, `latest-linux.yml` and
`latest-linux-arm64.yml`. Each leg writes its own feed; the draft job merges them into those four
(`scripts/merge-update-feeds.mjs`), then `scripts/feed-checksums.mjs write` checks every feed entry's
size and sha512 against the file it names and records the four feeds' SHA-256 in
`SHA256SUMS-update-feeds.txt`. Promotion runs `feed-checksums.mjs verify` on the downloaded draft and
refuses a feed that no longer matches its record or its files.

## Update signatures

Every file a feed names is signed with Clarity's update key, and the app refuses an update without that
signature. The draft job runs `scripts/sign-updates.mjs sign` after the feeds are checksummed; it writes
`<file>.sig` beside each file and `update-key.pub` (the public half). Promotion runs `sign-updates.mjs verify`
before it publishes.

What is signed is one line per file: `clarity-update-v1`, the version, the file name and the file's sha512. The
version and name are in it so an old signed installer cannot be served as a newer release.

- The private key is the secret `UPDATE_SIGNING_KEY`. Only the draft job reads it, and that job runs only this
  repository's scripts: a build leg runs the source's code and is never handed it.
- The public half is the variable `UPDATE_PUBLIC_KEY`, and the source pins the same value. Each leg's
  verification record carries the key its source pins, and signing with any other key is refused: every installed
  copy would reject that release's successors.
- Before the key is made, neither side names one and a release goes out unsigned and says so. Once either side
  names a key, an unsigned release is refused in both steps.

The source repository checks the same fixed test vector as `scripts/self-test.mjs` here, so the two cannot drift
apart on the signed text.
