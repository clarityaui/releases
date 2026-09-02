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
  windows: 'clarity-aui-1.2.3-x64.exe',
  macos: 'clarity-aui-1.2.3-x64.dmg',
  linux: 'clarity-aui-1.2.3-x86_64.AppImage'
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
        signed: channel === 'public-beta' && platform !== 'linux'
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
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
}

console.log('PASS: controller workflow boundary and manifest tamper rejection verified')
