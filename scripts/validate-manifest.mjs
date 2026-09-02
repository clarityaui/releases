import { createHash } from 'node:crypto'
import { basename, join, resolve } from 'node:path'
import { readFileSync } from 'node:fs'

const [manifestArg, directoryArg, tag, sourceShaArg, channel] = process.argv.slice(2)
const sourceSha = (sourceShaArg || '').toLowerCase()
if (!manifestArg || !directoryArg || !/^v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(tag || '') ||
    !/^[0-9a-f]{40}$/.test(sourceSha) || !['internal-unsigned', 'public-beta'].includes(channel)) {
  console.error('usage: node scripts/validate-manifest.mjs <manifest> <asset-dir> <vX.Y.Z> <source-sha> <channel>')
  process.exit(2)
}

const directory = resolve(directoryArg)
const manifest = JSON.parse(readFileSync(resolve(manifestArg), 'utf8'))
if (manifest.schema !== 1 || manifest.version !== tag.slice(1) || manifest.tag !== tag || manifest.channel !== channel) {
  throw new Error('manifest identity does not match the promotion request')
}
if (manifest.source?.repository !== 'clarityaui/main' || manifest.source?.sha !== sourceSha) {
  throw new Error('manifest source identity does not match')
}
if (!Number.isFinite(Date.parse(manifest.generated_at))) throw new Error('invalid manifest timestamp')
if (!Array.isArray(manifest.platforms) || manifest.platforms.length !== 3) throw new Error('manifest must contain exactly three platforms')

const expected = new Map([
  ['windows', { extension: '.exe', signed: channel === 'public-beta' }],
  ['macos', { extension: '.dmg', signed: channel === 'public-beta' }],
  ['linux', { extension: '.AppImage', signed: false }]
])
const seen = new Set()
const releaseBase = `https://github.com/clarityaui/releases/releases/download/${encodeURIComponent(tag)}/`
for (const platform of manifest.platforms) {
  const spec = expected.get(platform.id)
  if (!spec || seen.has(platform.id)) throw new Error(`unexpected or duplicate platform: ${platform.id}`)
  seen.add(platform.id)
  if (typeof platform.file !== 'string' || basename(platform.file) !== platform.file ||
      !/^[A-Za-z0-9][A-Za-z0-9._+-]*$/.test(platform.file) || !platform.file.endsWith(spec.extension)) {
    throw new Error(`unsafe or invalid installer filename for ${platform.id}`)
  }
  if (platform.url !== `${releaseBase}${encodeURIComponent(platform.file)}`) throw new Error(`invalid release URL for ${platform.id}`)
  if (!/^[0-9a-f]{64}$/.test(platform.sha256 || '')) throw new Error(`invalid checksum for ${platform.id}`)
  if (platform.verified !== true || platform.signed !== spec.signed) throw new Error(`invalid verification claim for ${platform.id}`)
  const actual = createHash('sha256').update(readFileSync(join(directory, platform.file))).digest('hex')
  if (actual !== platform.sha256) throw new Error(`artifact checksum mismatch for ${platform.id}`)
}
if (seen.size !== expected.size) throw new Error('manifest is missing a required platform')
console.log(`validated ${channel} release ${tag} from ${sourceSha}`)
