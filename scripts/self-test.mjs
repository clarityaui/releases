import { createHash } from 'node:crypto'
import { execFileSync, spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

const root = resolve(new URL('..', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'))
const candidate = readFileSync(join(root, '.github', 'workflows', 'candidate.yml'), 'utf8')
const promotion = readFileSync(join(root, '.github', 'workflows', 'promote.yml'), 'utf8')
const checks = readFileSync(join(root, '.github', 'workflows', 'controller-checks.yml'), 'utf8')

function assert(condition, message) {
  if (!condition) throw new Error(message)
}

for (const workflow of [candidate, promotion, checks]) {
  assert(!/uses:\s+[^\s#]+@(main|master|v\d+)\b/.test(workflow), 'every external action must be pinned to a commit')
}
assert(/SOURCE_REPO_TOKEN/.test(candidate) && /compare\/\$\{\{ inputs\.source_sha \}\}\.\.\.main/.test(candidate), 'candidate must verify private-source ancestry')
assert(/persisting credentials/.test(candidate) && /source\/package-lock\.json/.test(candidate), 'source must be fetched before source-controlled commands execute')
assert(!/GH_RELEASE_TOKEN|CLOUDFLARE_API_TOKEN/.test(candidate + promotion), 'controller must use no long-lived publishing or Cloudflare token')
const unprivilegedBuild = candidate.slice(candidate.indexOf('\n  build:'), candidate.indexOf('\n  draft:'))
assert(!/contents:\s*write/.test(unprivilegedBuild) && !/GH_TOKEN/.test(unprivilegedBuild), 'source build job must have no publishing authority')
assert(/\n  draft:[\s\S]*contents: write/.test(candidate), 'only the isolated draft job may create a release')
assert(/environment:.*public-beta/.test(promotion) && /PROMOTE \$\{\{ inputs\.tag \}\}/.test(promotion), 'promotion must use a protected environment and exact acknowledgement')
assert(/Get-AuthenticodeSignature/.test(candidate) && /codesign --verify/.test(candidate) && /stapler validate/.test(candidate), 'public beta must verify both platform trust chains')

const sourceSha = '0123456789abcdef0123456789abcdef01234567'
const assets = {
  'windows-x64': 'clarity-aui-1.2.3-x64.exe',
  'windows-arm64': 'clarity-aui-1.2.3-arm64.exe',
  'macos-arm64': 'clarity-aui-1.2.3-arm64.dmg',
  'macos-x64': 'clarity-aui-1.2.3-x64.dmg',
  'linux-x64': 'clarity-aui-1.2.3-x86_64.AppImage',
  'linux-arm64': 'clarity-aui-1.2.3-arm64.AppImage'
}

for (const channel of ['internal-unsigned', 'public-beta']) {
  const directory = mkdtempSync(join(tmpdir(), 'clarity-release-control-'))
  try {
    for (const [platform, name] of Object.entries(assets)) {
      writeFileSync(join(directory, name), `fixture-${channel}-${platform}`)
      const sha256 = createHash('sha256').update(readFileSync(join(directory, name))).digest('hex')
      writeFileSync(join(directory, `SHA256SUMS-${platform}.txt`), `${sha256}  ${name}\n`)
      writeFileSync(join(directory, `verification-${platform}.json`), JSON.stringify({
        schema: 1,
        platform,
        channel,
        source_sha: sourceSha,
        verified: true,
        signed: channel === 'public-beta' && !platform.startsWith('linux')
      }))
    }
    const manifest = join(directory, 'release-manifest.json')
    execFileSync(process.execPath, [join(root, 'scripts', 'assemble-manifest.mjs'), directory, 'v1.2.3', sourceSha, channel, manifest], { stdio: 'inherit' })
    execFileSync(process.execPath, [join(root, 'scripts', 'validate-manifest.mjs'), manifest, directory, 'v1.2.3', sourceSha, channel], { stdio: 'inherit' })
    const tampered = JSON.parse(readFileSync(manifest, 'utf8'))
    tampered.platforms[0].sha256 = '0'.repeat(64)
    writeFileSync(manifest, JSON.stringify(tampered))
    const rejected = spawnSync(process.execPath, [join(root, 'scripts', 'validate-manifest.mjs'), manifest, directory, 'v1.2.3', sourceSha, channel]).status !== 0
    assert(rejected, `tampered ${channel} manifest was accepted`)
    // Six legs, every one required: a manifest that quietly drops one (say, the Intel Mac) must not validate.
    // Assembled afresh so the ONLY thing wrong with it is the count — the checksum tamper above is not reused.
    const shortManifest = join(directory, 'release-manifest-short.json')
    execFileSync(process.execPath, [join(root, 'scripts', 'assemble-manifest.mjs'), directory, 'v1.2.3', sourceSha, channel, shortManifest], { stdio: 'ignore' })
    const short = JSON.parse(readFileSync(shortManifest, 'utf8'))
    assert(short.platforms.length === 6, 'the assembler produced six platforms')
    short.platforms = short.platforms.slice(0, 5)
    writeFileSync(shortManifest, JSON.stringify(short))
    const shortRejected = spawnSync(process.execPath, [join(root, 'scripts', 'validate-manifest.mjs'), shortManifest, directory, 'v1.2.3', sourceSha, channel]).status !== 0
    assert(shortRejected, `a ${channel} manifest with five of six platforms was accepted`)
    // …and a leg whose file carries the other arch is refused by the assembler, not renamed into place.
    const wrongArch = mkdtempSync(join(tmpdir(), 'clarity-release-control-arch-'))
    try {
      for (const [platform, name] of Object.entries(assets)) {
        const renamed = platform === 'windows-arm64' ? 'clarity-aui-1.2.3-x64-second.exe' : name
        writeFileSync(join(wrongArch, renamed), `fixture-${channel}-${platform}`)
        const sha256 = createHash('sha256').update(readFileSync(join(wrongArch, renamed))).digest('hex')
        writeFileSync(join(wrongArch, `SHA256SUMS-${platform}.txt`), `${sha256}  ${renamed}
`)
        writeFileSync(join(wrongArch, `verification-${platform}.json`), JSON.stringify({ schema: 1, platform, channel, source_sha: sourceSha, verified: true, signed: channel === 'public-beta' && !platform.startsWith('linux') }))
      }
      const archRejected = spawnSync(process.execPath, [join(root, 'scripts', 'assemble-manifest.mjs'), wrongArch, 'v1.2.3', sourceSha, channel, join(wrongArch, 'm.json')]).status !== 0
      assert(archRejected, `an arm64 leg whose installer is named x64 was assembled for ${channel}`)
    } finally {
      rmSync(wrongArch, { recursive: true, force: true })
    }
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
}

console.log('PASS: controller workflow boundary and manifest tamper rejection verified')
