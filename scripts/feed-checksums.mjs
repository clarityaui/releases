import { createHash } from 'node:crypto'
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'

/**
 * The update feeds get a checksum, and each must describe the files it ships.
 *
 *   node scripts/feed-checksums.mjs write  <dir>   candidate.yml's draft job, after merge-update-feeds.mjs
 *   node scripts/feed-checksums.mjs verify <dir>   promote.yml, on the downloaded draft
 *
 * ⚠⚠ The four canonical feeds are what electron-updater downloads to decide what to install, and they were the only
 *    published files with no checksum. Each leg checksums its own per-leg feed; merge-update-feeds.mjs then builds the
 *    canonical feeds from those and deletes the per-leg copies, so no record covered what was actually published.
 *
 * Both modes first check every feed against the release it sits in: each `url` is a file in the directory, and the
 * feed's `size` and `sha512` are that file's. `write` then records the four feeds' SHA-256 in
 * SHA256SUMS-update-feeds.txt; `verify` requires that record back, exactly. No YAML dependency, for the same reason
 * as merge-update-feeds.mjs: the format is electron-builder's own machine output, and anything unexpected refuses.
 */

const FEEDS = ['latest.yml', 'latest-mac.yml', 'latest-linux.yml', 'latest-linux-arm64.yml']
const SUMS = 'SHA256SUMS-update-feeds.txt'
const SAFE = /^[A-Za-z0-9][A-Za-z0-9._+-]*$/

const [mode, directoryArg] = process.argv.slice(2)
if (!['write', 'verify'].includes(mode) || !directoryArg) {
  console.error('usage: node scripts/feed-checksums.mjs <write|verify> <dir>')
  process.exit(2)
}
const directory = resolve(directoryArg)
const digest = (algorithm, name, encoding) => createHash(algorithm).update(readFileSync(join(directory, name))).digest(encoding)
const isFile = (name) => existsSync(join(directory, name)) && statSync(join(directory, name)).isFile()

/** A feed's `files:` entries plus its top-level `version`, `path` and `sha512`. */
function readFeed(name) {
  const lines = readFileSync(join(directory, name), 'utf8').split(/\r?\n/)
  const top = (key) => {
    const line = lines.find((l) => l.startsWith(`${key}: `))
    return line ? line.slice(key.length + 2).trim().replace(/^'(.*)'$/, '$1') : ''
  }
  const start = lines.indexOf('files:')
  if (start < 0) throw new Error(`${name}: no top-level "files:" key — electron-builder's feed format changed`)
  const entries = []
  for (let i = start + 1; i < lines.length && /^\s+\S/.test(lines[i]); i++) {
    const item = /^ {2}- url: (\S+)$/.exec(lines[i])
    if (item) {
      entries.push({ url: item[1] })
      continue
    }
    const field = /^ {4}(sha512|size): (\S+)$/.exec(lines[i])
    if (field && entries.length) entries[entries.length - 1][field[1]] = field[2]
  }
  if (!entries.length) throw new Error(`${name}: "files:" names no file`)
  return { version: top('version'), path: top('path'), sha512: top('sha512'), entries }
}

let checked = 0
const versions = new Set()
for (const name of FEEDS) {
  if (!isFile(name)) throw new Error(`${name} is missing — electron-updater asks for it by that name`)
  const feed = readFeed(name)
  versions.add(feed.version)
  for (const entry of feed.entries) {
    if (!SAFE.test(entry.url)) throw new Error(`${name}: unsafe or quoted url ${entry.url}`)
    if (!isFile(entry.url)) throw new Error(`${name} names ${entry.url}, which is not in this release`)
    if (!/^\d+$/.test(entry.size || '') || Number(entry.size) !== statSync(join(directory, entry.url)).size) {
      throw new Error(`${name}: the size it gives ${entry.url} (${entry.size}) is not the file's`)
    }
    if (entry.sha512 !== digest('sha512', entry.url, 'base64')) throw new Error(`${name}: the sha512 it gives ${entry.url} is not the file's`)
    checked++
  }
  // The legacy top-level fields older clients read must name one of the files above, with the same hash.
  if (!feed.entries.some((e) => e.url === feed.path && e.sha512 === feed.sha512)) {
    throw new Error(`${name}: its top-level path/sha512 (${feed.path}) is not one of its files`)
  }
}
if (versions.size !== 1 || !versions.values().next().value) throw new Error(`the four feeds disagree on the version: ${[...versions].join(', ')}`)

if (mode === 'write') {
  // ⚠ Linux arm64's per-leg name IS its canonical name, so it is never a leftover (caught on the beta.6 dry run).
  const leftovers = readdirSync(directory).filter((n) => /^latest-(windows|macos|linux)-(x64|arm64)\.yml$/.test(n) && !FEEDS.includes(n))
  if (leftovers.length) throw new Error(`per-leg feeds are still here (${leftovers.join(', ')}); run merge-update-feeds.mjs first`)
  if (existsSync(join(directory, SUMS))) throw new Error(`${SUMS} already exists; refusing to overwrite a record`)
  writeFileSync(join(directory, SUMS), FEEDS.map((name) => `${digest('sha256', name, 'hex')}  ${name}\n`).join(''))
} else {
  if (!isFile(SUMS)) throw new Error(`${SUMS} is missing — the update feeds would publish with no checksum`)
  const recorded = new Map()
  for (const line of readFileSync(join(directory, SUMS), 'utf8').split(/\r?\n/).filter(Boolean)) {
    const match = /^([0-9a-f]{64}) {2}(\S+)$/.exec(line)
    if (!match || recorded.has(match[2])) throw new Error(`${SUMS}: unreadable or repeated line "${line}"`)
    recorded.set(match[2], match[1])
  }
  if ([...recorded.keys()].sort().join() !== [...FEEDS].sort().join()) {
    throw new Error(`${SUMS} covers ${[...recorded.keys()].join(', ')}; it must cover exactly ${FEEDS.join(', ')}`)
  }
  for (const name of FEEDS) {
    if (recorded.get(name) !== digest('sha256', name, 'hex')) throw new Error(`${name} does not match its recorded checksum`)
  }
}
console.log(`${mode === 'write' ? 'wrote' : 'verified'} ${SUMS}: ${FEEDS.length} feeds, ${checked} files each matching its feed's size and sha512 (version ${[...versions][0]})`)
