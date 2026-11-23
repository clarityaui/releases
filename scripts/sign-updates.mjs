import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto'
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'

/**
 * Every file an update feed names gets Clarity's signature, and promotion checks each one back.
 *
 *   node scripts/sign-updates.mjs sign   <dir>   candidate.yml's draft job, after feed-checksums.mjs write
 *   node scripts/sign-updates.mjs verify <dir>   promote.yml, on the downloaded draft
 *
 * ⚠⚠ Until this existed a Windows or AppImage update was trusted because GitHub served it: electron-updater checks the
 *    installer's sha512 against the feed, and both come from the same release, so whoever could write a release could
 *    ship any installer to every running copy (the Windows build is not code-signed, an AppImage never is). The app
 *    now carries the public half of the key this script signs with and refuses an installer without its signature
 *    (src/main/updateSignature.ts in the source).
 *
 * What is signed is one line of text per file, never the bytes alone:
 *
 *     clarity-update-v1 \n <version> \n <file name> \n <sha512 of the file, base64> \n
 *
 * ⚠ The version and the name are in the text so that an old, validly signed installer cannot be served as a new
 *   release. The app builds the same text from the version the feed promised. The two repositories are held to one
 *   format by a fixed test vector that both check (self-test.mjs here, scripts/updatesig-test.ts there).
 *
 * `sign` reads the key from UPDATE_SIGNING_KEY (an Ed25519 private key, PKCS#8 PEM) and writes `<file>.sig` (the
 * signature, base64, one line) beside each file, plus `update-key.pub` (the public half: the raw 32 bytes, base64).
 *
 * WHEN A SIGNATURE IS REQUIRED. Signing is owed as soon as either side says a key exists: the source pins one (each
 * leg's verification record carries what `src/shared/updateKey.ts` held in the commit it built), or this repository's
 * UPDATE_PUBLIC_KEY variable names one. Before the key is made, neither does, and a release goes out unsigned and says
 * so, exactly as before. After, an unsigned release is refused in both steps.
 *
 * ⚠⚠ A release signed with a key OTHER than the one its own source pins is refused, loudly: every installed copy of
 *    that source would reject every later update, and nothing short of a manual reinstall would bring them back.
 *
 * A release with some signatures and not others is always refused. No YAML dependency, for the same reason as
 * feed-checksums.mjs: the feed is electron-builder's own machine output, and anything unexpected refuses.
 */

export const CONTEXT = 'clarity-update-v1'
const FEEDS = ['latest.yml', 'latest-mac.yml', 'latest-linux.yml', 'latest-linux-arm64.yml']
const KEY_FILE = 'update-key.pub'
const SAFE = /^[A-Za-z0-9][A-Za-z0-9._+-]*$/
const RAW_KEY = /^[A-Za-z0-9+/]{43}=$/
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')

export const signedText = (version, name, sha512Base64) => `${CONTEXT}\n${version}\n${name}\n${sha512Base64}\n`

/** The raw 32-byte public key (base64) of an Ed25519 private key. */
export function publicKeyOf(privateKey) {
  const der = createPublicKey(privateKey).export({ format: 'der', type: 'spki' })
  return der.subarray(der.length - 32).toString('base64')
}

export function signOne(privateKey, version, name, sha512Base64) {
  return sign(null, Buffer.from(signedText(version, name, sha512Base64), 'utf8'), privateKey).toString('base64')
}

export function verifyOne(publicKeyBase64, version, name, sha512Base64, signatureBase64) {
  const sig = Buffer.from(String(signatureBase64).trim(), 'base64')
  if (!RAW_KEY.test(publicKeyBase64) || sig.length !== 64) return false
  const key = createPublicKey({ key: Buffer.concat([SPKI_PREFIX, Buffer.from(publicKeyBase64, 'base64')]), format: 'der', type: 'spki' })
  return verify(null, Buffer.from(signedText(version, name, sha512Base64), 'utf8'), key, sig)
}

/** Each feed's version and the files it names, once per file. One file under two versions refuses. */
export function feedFiles(directory) {
  const out = new Map()
  for (const feed of FEEDS) {
    const path = join(directory, feed)
    if (!existsSync(path)) throw new Error(`${feed} is missing: sign after merge-update-feeds.mjs has run`)
    const lines = readFileSync(path, 'utf8').split(/\r?\n/)
    const versionLine = lines.find((l) => l.startsWith('version: '))
    const version = versionLine ? versionLine.slice(9).trim().replace(/^'(.*)'$/, '$1') : ''
    if (!/^\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$/.test(version)) throw new Error(`${feed}: no usable version (${version || 'none'})`)
    const start = lines.indexOf('files:')
    if (start < 0) throw new Error(`${feed}: no top-level "files:" key`)
    let named = 0
    for (let i = start + 1; i < lines.length && /^\s+\S/.test(lines[i]); i++) {
      const item = /^ {2}- url: (\S+)$/.exec(lines[i])
      if (!item) continue
      const name = item[1]
      if (!SAFE.test(name)) throw new Error(`${feed}: unsafe or quoted url ${name}`)
      if (out.has(name) && out.get(name) !== version) throw new Error(`${name} is named under two versions (${out.get(name)}, ${version})`)
      out.set(name, version)
      named++
    }
    if (!named) throw new Error(`${feed}: "files:" names no file`)
  }
  return [...out].map(([name, version]) => ({ name, version })).sort((a, b) => (a.name < b.name ? -1 : 1))
}

/** The key the built source pins, from the legs' verification records. All legs build one commit, so one answer. */
export function pinnedKey(directory) {
  const keys = new Set()
  for (const name of readdirSync(directory).filter((n) => /^verification-[a-z0-9-]+\.json$/.test(n))) {
    const record = JSON.parse(readFileSync(join(directory, name), 'utf8'))
    const key = typeof record.update_key === 'string' ? record.update_key : ''
    if (key && !RAW_KEY.test(key)) throw new Error(`${name}: update_key is not a raw Ed25519 public key`)
    keys.add(key)
  }
  if (keys.size > 1) throw new Error(`the legs disagree on the update key their source pins: ${[...keys].map((k) => k || 'none').join(', ')}`)
  return keys.size ? [...keys][0] : ''
}

const sha512 = (path) => createHash('sha512').update(readFileSync(path)).digest('base64')

export function run(mode, directoryArg, env = process.env, log = console.log) {
  const directory = resolve(directoryArg)
  const files = feedFiles(directory)
  for (const f of files) {
    if (!existsSync(join(directory, f.name)) || !statSync(join(directory, f.name)).isFile()) throw new Error(`a feed names ${f.name}, which is not in this release`)
  }
  const sigs = readdirSync(directory).filter((n) => n.endsWith('.sig'))
  const hasKeyFile = existsSync(join(directory, KEY_FILE))
  const pinned = pinnedKey(directory)
  const expected = (env.UPDATE_PUBLIC_KEY || '').trim()
  if (expected && !RAW_KEY.test(expected)) throw new Error('UPDATE_PUBLIC_KEY is not a raw Ed25519 public key')
  if (pinned && expected && pinned !== expected) throw new Error(`the source pins ${pinned} and this controller expects ${expected}: one of them is wrong, and nothing is signed until they agree`)
  const required = pinned || expected

  if (mode === 'sign') {
    if (sigs.length || hasKeyFile) throw new Error('this directory already carries signatures: sign a fresh staging directory')
    const pem = env.UPDATE_SIGNING_KEY || ''
    if (!pem.trim()) {
      if (required) throw new Error(`UPDATE_SIGNING_KEY is not set, but a key exists (${required}): this release must be signed with it`)
      log(`NOT SIGNED: no update key has been made. ${files.length} update file(s) ship without Clarity's signature, as before.`)
      return { signed: 0, files: files.length }
    }
    const key = createPrivateKey(pem)
    if (key.asymmetricKeyType !== 'ed25519') throw new Error(`UPDATE_SIGNING_KEY is ${key.asymmetricKeyType}, not ed25519`)
    const pub = publicKeyOf(key)
    if (required && pub !== required) throw new Error(`UPDATE_SIGNING_KEY's public half is ${pub}, not the key in use (${required}): every installed copy would refuse this release's successors`)
    for (const f of files) {
      const hash = sha512(join(directory, f.name))
      const sig = signOne(key, f.version, f.name, hash)
      if (!verifyOne(pub, f.version, f.name, hash, sig)) throw new Error(`the signature just made for ${f.name} does not verify`)
      writeFileSync(join(directory, `${f.name}.sig`), `${sig}\n`)
    }
    writeFileSync(join(directory, KEY_FILE), `${pub}\n`)
    log(`signed ${files.length} update file(s); public key ${pub}${pinned ? '' : ' (the source pins no key yet, so no installed copy checks these)'}`)
    return { signed: files.length, files: files.length, publicKey: pub }
  }

  if (mode === 'verify') {
    if (!hasKeyFile && !sigs.length) {
      if (required) throw new Error(`this release carries no update signatures, but a key exists (${required})`)
      log(`NOT SIGNED: ${files.length} update file(s) carry no signature; no update key has been made.`)
      return { verified: 0, files: files.length }
    }
    if (!hasKeyFile) throw new Error(`${KEY_FILE} is missing beside ${sigs.length} signature(s)`)
    const pub = readFileSync(join(directory, KEY_FILE), 'utf8').trim()
    if (!RAW_KEY.test(pub)) throw new Error(`${KEY_FILE} is not a raw Ed25519 public key`)
    if (required && pub !== required) throw new Error(`this release was signed with ${pub}, not the key in use (${required})`)
    const wanted = new Set(files.map((f) => `${f.name}.sig`))
    for (const s of sigs) if (!wanted.has(s)) throw new Error(`${s} signs a file no feed names`)
    for (const f of files) {
      const sigPath = join(directory, `${f.name}.sig`)
      if (!existsSync(sigPath)) throw new Error(`${f.name} has no signature, though others in this release do`)
      if (!verifyOne(pub, f.version, f.name, sha512(join(directory, f.name)), readFileSync(sigPath, 'utf8'))) {
        throw new Error(`${f.name}: its signature does not verify for version ${f.version}`)
      }
    }
    log(`verified ${files.length} update signature(s) against ${pub}`)
    return { verified: files.length, files: files.length, publicKey: pub }
  }
  throw new Error('usage: node scripts/sign-updates.mjs <sign|verify> <dir>')
}

const invoked = process.argv[1] ? resolve(process.argv[1]) : ''
if (invoked && invoked === resolve(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'))) {
  const [mode, directoryArg] = process.argv.slice(2)
  if (!['sign', 'verify'].includes(mode) || !directoryArg) {
    console.error('usage: node scripts/sign-updates.mjs <sign|verify> <dir>')
    process.exit(2)
  }
  try {
    run(mode, directoryArg)
  } catch (error) {
    console.error(`::error::${error.message}`)
    process.exit(1)
  }
}
