import { readFileSync, writeFileSync, rmSync, existsSync } from 'node:fs'
import { join, resolve } from 'node:path'

/**
 * Rebuild electron-updater's canonical feeds from the per-leg ones the build jobs upload.
 *
 * ⚠⚠⚠ WHY THIS EXISTS. electron-builder names its update feed after the PLATFORM, never the arch: both Windows
 *     legs write `latest.yml` and both macOS legs write `latest-mac.yml`. candidate.yml downloads all six legs
 *     with `merge-multiple: true` into one flat directory, so the second mac leg's feed simply OVERWROTE the
 *     first — and whichever won described a single architecture. Publishing that ships an update feed that does
 *     not mention half the Mac users' build. The only reason this was caught is that both legs' SHA256SUMS
 *     recorded the same file name with different hashes and assemble-manifest refused the conflict; the first
 *     all-six-green candidate (2026-09-21) died there rather than shipping a half feed.
 *
 *     So the build jobs now rename their feed to `latest-<leg>.yml` (unique per leg, no overwrite, and
 *     assemble-manifest's collision check stays strict for everything else), and this script puts the canonical
 *     names back — merging the two-arch families instead of letting one win.
 *
 * ⚠⚠ THE RENAME ALONE WOULD HAVE BROKEN LINUX. Publishing only `latest-linux-x64.yml` means no AppImage client
 *    ever finds `latest-linux.yml` again. Every family is reconstructed here, not just the merged ones.
 *
 * No YAML dependency: this repository deliberately has no package.json, and a release controller is the last
 * place to add a supply chain. The merge is structural over electron-builder's own machine-generated output,
 * and it is guarded — every merged feed must name each architecture it claims to cover, or this throws. If the
 * generator's format ever changes, that assertion fails loudly instead of emitting a quietly truncated feed.
 */

const directory = resolve(process.argv[2] || '')
if (!process.argv[2]) {
  console.error('usage: node scripts/merge-update-feeds.mjs <staged-dir>')
  process.exit(2)
}

/** canonical = what electron-updater asks for; legs = the per-leg feeds that compose it, in precedence order. */
const families = [
  { canonical: 'latest.yml', legs: ['windows-x64', 'windows-arm64'], arches: ['-x64.exe', '-arm64.exe'] },
  { canonical: 'latest-mac.yml', legs: ['macos-arm64', 'macos-x64'], arches: ['-arm64.', '-x64.'] },
  { canonical: 'latest-linux.yml', legs: ['linux-x64'], arches: ['-x86_64.AppImage'] },
  { canonical: 'latest-linux-arm64.yml', legs: ['linux-arm64'], arches: ['-arm64.AppImage'] }
]

/** The `files:` list of an electron-builder feed: the top-level key, then every indented line under it. */
function splitFeed(text, name) {
  const lines = text.split(/\r?\n/)
  const start = lines.findIndex((line) => line === 'files:')
  if (start < 0) throw new Error(`${name}: no top-level "files:" key — electron-builder's feed format changed`)
  let end = start + 1
  while (end < lines.length && /^\s+\S/.test(lines[end])) end++
  const entries = lines.slice(start + 1, end)
  if (!entries.length) throw new Error(`${name}: "files:" is empty`)
  return { before: lines.slice(0, start + 1), entries, after: lines.slice(end) }
}

for (const family of families) {
  const present = family.legs.filter((leg) => existsSync(join(directory, `latest-${leg}.yml`)))
  if (present.length !== family.legs.length) {
    throw new Error(`${family.canonical}: expected a feed from ${family.legs.join(' and ')}, found ${present.length}`)
  }
  const parts = present.map((leg) => {
    const name = `latest-${leg}.yml`
    return { name, ...splitFeed(readFileSync(join(directory, name), 'utf8'), name) }
  })
  // The first leg supplies version/path/releaseDate; the rest contribute only their files entries.
  const [base, ...rest] = parts
  const merged = [...base.before, ...base.entries, ...rest.flatMap((p) => p.entries), ...base.after].join('\n')

  // ⚠ The assertion that makes a dependency-free merge safe: a feed that lost an architecture is the exact
  //   defect this script exists to prevent, so it must never be written.
  for (const arch of family.arches) {
    if (!merged.includes(arch)) {
      throw new Error(`${family.canonical}: merged feed never names ${arch} — it would leave that architecture without an update`)
    }
  }
  writeFileSync(join(directory, family.canonical), merged)
  for (const part of parts) if (part.name !== family.canonical) rmSync(join(directory, part.name))
  console.log(`${family.canonical}: ${parts.map((p) => p.name).join(' + ')} → ${family.arches.join(', ')}`)
}
