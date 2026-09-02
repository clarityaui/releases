import { createHash } from 'node:crypto'
import { basename, join, resolve } from 'node:path'
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs'

const [directoryArg, tag, sourceShaArg, channel, outputArg] = process.argv.slice(2)
const sourceSha = (sourceShaArg || '').toLowerCase()
if (!directoryArg || !/^v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(tag || '') ||
    !/^[0-9a-f]{40}$/.test(sourceSha) || !['internal-unsigned', 'public-beta'].includes(channel) || !outputArg) {
  console.error('usage: node scripts/assemble-manifest.mjs <asset-dir> <vX.Y.Z> <source-sha> <channel> <output>')
  process.exit(2)
}

const directory = resolve(directoryArg)
const names = readdirSync(directory).filter((name) => statSync(join(directory, name)).isFile())
for (const name of names) {
  if (basename(name) !== name || !/^[A-Za-z0-9][A-Za-z0-9._+-]*$/.test(name)) throw new Error(`unsafe asset name: ${name}`)
}

const checksums = new Map()
for (const name of names.filter((value) => /^SHA256SUMS-(windows|macos|linux)\.txt$/.test(value))) {
  for (const line of readFileSync(join(directory, name), 'utf8').split(/\r?\n/)) {
    const match = line.match(/^([0-9A-Fa-f]{64})\s+([A-Za-z0-9][A-Za-z0-9._+-]*)$/)
    if (!match) continue
    const asset = match[2]
    if (checksums.has(asset) && checksums.get(asset) !== match[1].toLowerCase()) throw new Error(`conflicting checksum for ${asset}`)
    checksums.set(asset, match[1].toLowerCase())
  }
}

const specs = [
  { id: 'windows', label: 'Windows', extension: '.exe' },
  { id: 'macos', label: 'macOS', extension: '.dmg' },
  { id: 'linux', label: 'Linux', extension: '.AppImage' }
]
const releaseBase = `https://github.com/clarityaui/releases/releases/download/${encodeURIComponent(tag)}`
const platforms = specs.map((spec) => {
  const verificationPath = join(directory, `verification-${spec.id}.json`)
  const verification = JSON.parse(readFileSync(verificationPath, 'utf8'))
  if (verification.schema !== 1 || verification.platform !== spec.id || verification.channel !== channel ||
      verification.source_sha !== sourceSha || verification.verified !== true) {
    throw new Error(`invalid verification record for ${spec.id}`)
  }
  const expectedSigned = channel === 'public-beta' && spec.id !== 'linux'
  if (verification.signed !== expectedSigned) throw new Error(`invalid signing claim for ${spec.id}`)
  const matches = names.filter((name) => name.endsWith(spec.extension))
  if (matches.length !== 1) throw new Error(`${spec.id} must have exactly one ${spec.extension} asset; found ${matches.length}`)
  const file = matches[0]
  const sha256 = checksums.get(file)
  if (!sha256) throw new Error(`missing checksum for ${file}`)
  const actual = createHash('sha256').update(readFileSync(join(directory, file))).digest('hex')
  if (actual !== sha256) throw new Error(`checksum mismatch for ${file}`)
  const meta = channel === 'public-beta'
    ? (spec.id === 'windows' ? 'x64 · signed exe' : spec.id === 'macos' ? 'signed and notarized dmg' : 'x64 · verified AppImage')
    : (spec.id === 'linux' ? 'x64 · internal unsigned build' : 'internal unsigned build')
  return {
    id: spec.id,
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
