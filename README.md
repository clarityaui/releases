# Clarity AUI release controller

This public repository is the release trust boundary for the private
[`clarityaui/main`](https://github.com/clarityaui/main) source repository. It contains no
application source.

## Security model

- `main` is protected. Release workflow changes must arrive through a pull request.
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
