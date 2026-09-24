import { createHash } from 'node:crypto'
import { basename, join, resolve } from 'node:path'
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs'
import { isChannel, signedFor } from './channels.mjs'

const [directoryArg, tag, sourceShaArg, channel, outputArg] = process.argv.slice(2)
const sourceSha = (sourceShaArg || '').toLowerCase()
if (!directoryArg || !/^v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(tag || '') ||
    !/^[0-9a-f]{40}$/.test(sourceSha) || !isChannel(channel) || !outputArg) {
  console.error('usage: node scripts/assemble-manifest.mjs <asset-dir> <vX.Y.Z> <source-sha> <channel> <output>')
  process.exit(2)
}

const directory = resolve(directoryArg)
const names = readdirSync(directory).filter((name) => statSync(join(directory, name)).isFile())
for (const name of names) {
  if (basename(name) !== name || !/^[A-Za-z0-9][A-Za-z0-9._+-]*$/.test(name)) throw new Error(`unsafe asset name: ${name}`)
}

const checksums = new Map()
for (const name of names.filter((value) => /^SHA256SUMS-(windows|macos|linux)-(x64|arm64)\.txt$/.test(value))) {
  for (const line of readFileSync(join(directory, name), 'utf8').split(/\r?\n/)) {
    const match = line.match(/^([0-9A-Fa-f]{64})\s+([A-Za-z0-9][A-Za-z0-9._+-]*)$/)
    if (!match) continue
    const asset = match[2]
    if (checksums.has(asset) && checksums.get(asset) !== match[1].toLowerCase()) throw new Error(`conflicting checksum for ${asset}`)
    checksums.set(asset, match[1].toLowerCase())
  }
}

/**
 * One entry per leg of candidate.yml's matrix. `pattern` is the arch electron-builder writes into the file name
 * (`artifactName: ${name}-${version}-${arch}.${ext}` in the source's electron-builder.yml): Windows and macOS say
 * `x64`/`arm64`, the AppImage says `x86_64`/`arm64`. Two legs share an extension now, so an extension alone no
 * longer names a platform.
 */
const specs = [
  { id: 'windows-x64', family: 'windows', arch: 'x64', label: 'Windows', extension: '.exe', pattern: /-x64\.exe$/ },
  { id: 'windows-arm64', family: 'windows', arch: 'arm64', label: 'Windows on ARM', extension: '.exe', pattern: /-arm64\.exe$/ },
  { id: 'macos-arm64', family: 'macos', arch: 'arm64', label: 'macOS (Apple silicon)', extension: '.dmg', pattern: /-arm64\.dmg$/ },
  { id: 'macos-x64', family: 'macos', arch: 'x64', label: 'macOS (Intel)', extension: '.dmg', pattern: /-x64\.dmg$/ },
  { id: 'linux-x64', family: 'linux', arch: 'x64', label: 'Linux', extension: '.AppImage', pattern: /-x86_64\.AppImage$/ },
  { id: 'linux-arm64', family: 'linux', arch: 'arm64', label: 'Linux (arm64)', extension: '.AppImage', pattern: /-arm64\.AppImage$/ }
]
const releaseBase = `https://github.com/clarityaui/releases/releases/download/${encodeURIComponent(tag)}`
const platforms = specs.map((spec) => {
  const verificationPath = join(directory, `verification-${spec.id}.json`)
  const verification = JSON.parse(readFileSync(verificationPath, 'utf8'))
  if (verification.schema !== 1 || verification.platform !== spec.id || verification.channel !== channel ||
      verification.source_sha !== sourceSha || verification.verified !== true) {
    throw new Error(`invalid verification record for ${spec.id}`)
  }
  const expectedSigned = signedFor(channel, spec.family)
  if (verification.signed !== expectedSigned) throw new Error(`invalid signing claim for ${spec.id}`)
  const matches = names.filter((name) => spec.pattern.test(name))
  if (matches.length !== 1) throw new Error(`${spec.id} must have exactly one ${spec.extension} asset for ${spec.arch}; found ${matches.length}`)
  const file = matches[0]
  const sha256 = checksums.get(file)
  if (!sha256) throw new Error(`missing checksum for ${file}`)
  const actual = createHash('sha256').update(readFileSync(join(directory, file))).digest('hex')
  if (actual !== sha256) throw new Error(`checksum mismatch for ${file}`)
  // Public-beta strings are unchanged; a mac-signed beta says which of its legs are signed and which are not.
  const meta = channel === 'internal-unsigned'
    ? `${spec.arch} · internal unsigned build`
    : expectedSigned
      ? (spec.family === 'windows' ? `${spec.arch} · signed exe` : `${spec.arch} · signed and notarized dmg`)
      : spec.family === 'linux' ? `${spec.arch} · verified AppImage` : `${spec.arch} · unsigned ${spec.family === 'windows' ? 'exe' : 'dmg'}`
  return {
    id: spec.id,
    family: spec.family,
    arch: spec.arch,
    label: spec.label,
    meta,
    file,
    url: `${releaseBase}/${encodeURIComponent(file)}`,
    sha256,
    verified: true,
    signed: expectedSigned
  }
})

const manifest = {
  schema: 1,
  version: tag.slice(1),
  tag,
  channel,
  source: { repository: 'clarityaui/main', sha: sourceSha },
  generated_at: new Date().toISOString(),
  platforms
}
writeFileSync(resolve(outputArg), JSON.stringify(manifest, null, 2) + '\n')
console.log(`assembled ${channel} manifest for ${tag} from ${sourceSha}`)
