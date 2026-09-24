import { createHash } from 'node:crypto'
import { execFileSync, spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { CHANNELS, signedFor } from './channels.mjs'

const root = resolve(new URL('..', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'))
// ⚠ Read with LF line endings whatever the checkout. The readers below match `\n`, and a Windows clone
//   (core.autocrlf=true, the default there) checks the workflows out with CRLF: the channel reader then found
//   no options at all and failed a clean tree. CI's Linux checkout is LF, so only a local run could see it.
const workflowText = (name) => readFileSync(join(root, '.github', 'workflows', name), 'utf8').replace(/\r\n/g, '\n')
const candidate = workflowText('candidate.yml')
const promotion = workflowText('promote.yml')
const checks = workflowText('controller-checks.yml')

function assert(condition, message) {
  if (!condition) throw new Error(message)
}

/**
 * ⚠⚠ DERIVED FROM THE DIRECTORY, NEVER HAND-WRITTEN. This loop used to read `[candidate, promotion, checks]`,
 *    so the moment a fourth workflow was added (source-checks.yml, 2026-09-21) it would have been the one file
 *    whose actions nobody checked were pinned — the list and its source silently disagreeing, which is the
 *    defect this rule exists for. Adding a workflow now adds its coverage.
 */
const workflowDir = join(root, '.github', 'workflows')
const workflowFiles = readdirSync(workflowDir).filter((name) => name.endsWith('.yml'))
assert(workflowFiles.length >= 4, `expected the controller's workflows, found ${workflowFiles.join(', ') || 'none'}`)
for (const name of workflowFiles) {
  const workflow = readFileSync(join(workflowDir, name), 'utf8')
  assert(!/uses:\s+[^\s#]+@(main|master|v\d+)\b/.test(workflow), `every external action must be pinned to a commit (${name})`)
}

/**
 * ⚠⚠⚠ THE CHEAP SUITE MUST STAY CHEAP IN AUTHORITY, NOT JUST IN MINUTES. source-checks runs the private source
 *     on public runners so the six platforms cost nothing; that is only safe while it cannot publish. It builds
 *     no installer and creates no release, so it has no business holding write permission or a token.
 */
const sourceChecks = readFileSync(join(workflowDir, 'source-checks.yml'), 'utf8')
assert(!/contents:\s*write/.test(sourceChecks), 'source-checks must not hold write permission')
assert(!/GH_TOKEN|gh release/.test(sourceChecks), 'source-checks must not be able to publish a release')
assert(!/CSC_LINK|APPLE_API_KEY|CSC_KEY_PASSWORD/.test(sourceChecks), 'source-checks must not reach the signing secrets')

/**
 * ⚠⚠⚠ SOME WORKFLOW KEYS ARE EVALUATED BEFORE A JOB'S MATRIX EXISTS, AND GITHUB REFUSES THE WHOLE FILE IF THEY READ
 *     IT. A job's `if:` and `strategy:` may read only github, needs, vars and inputs; the workflow's `concurrency:`
 *     and `run-name:` only github, inputs and vars. source-checks.yml's first cut narrowed its legs with
 *     `matrix.family` in the job `if:`, and no leg ever ran: a push showed one failed run named after the file's
 *     path, and every check here was green because none of them read an expression's contexts. Now every workflow's
 *     restricted expressions are read, and the count is printed so a reader that finds nothing cannot pass.
 */
const ALLOWED = {
  'job if': new Set(['github', 'needs', 'vars', 'inputs']),
  'job strategy': new Set(['github', 'needs', 'vars', 'inputs']),
  'workflow concurrency': new Set(['github', 'inputs', 'vars']),
  'workflow run-name': new Set(['github', 'inputs', 'vars'])
}
const contextsIn = (expr) =>
  [...expr.replace(/'[^']*'/g, "''").matchAll(/(?<![\w.-])([A-Za-z_][\w-]*)\s*\./g)].map((m) => m[1])
const bracesOf = (line) => [...line.matchAll(/\$\{\{([\s\S]*?)\}\}/g)].map((m) => m[1])
function restrictedExpressions(text) {
  const out = []
  let top = null
  let job = null
  let jobKey = null
  for (const line of text.split(/\r?\n/)) {
    if (/^\s*#/.test(line) || !line.trim()) continue
    const t = /^([\w-]+):\s*(.*)$/.exec(line)
    if (t) {
      top = t[1]
      job = null
      jobKey = null
      if (top === 'run-name') out.push({ where: 'workflow run-name', of: 'the workflow', expr: t[2] })
      if (top === 'concurrency') for (const e of bracesOf(t[2])) out.push({ where: 'workflow concurrency', of: 'the workflow', expr: e })
      continue
    }
    if (top === 'concurrency') {
      for (const e of bracesOf(line)) out.push({ where: 'workflow concurrency', of: 'the workflow', expr: e })
      continue
    }
    if (top !== 'jobs') continue
    const j = /^  ([\w-]+):\s*$/.exec(line)
    if (j) {
      job = j[1]
      jobKey = null
      continue
    }
    const k = /^    ([\w-]+):\s*(.*)$/.exec(line)
    if (k) {
      jobKey = k[1]
      if (jobKey === 'if') out.push({ where: 'job if', of: `job ${job}`, expr: k[2] })
      if (jobKey === 'strategy') for (const e of bracesOf(k[2])) out.push({ where: 'job strategy', of: `job ${job}`, expr: e })
      continue
    }
    if (jobKey === 'strategy') for (const e of bracesOf(line)) out.push({ where: 'job strategy', of: `job ${job}`, expr: e })
  }
  return out
}
const restrictedRead = []
for (const name of workflowFiles) {
  for (const { where, of, expr } of restrictedExpressions(readFileSync(join(workflowDir, name), 'utf8'))) {
    restrictedRead.push(`${name} · ${of} · ${where.split(' ')[1]}: ${expr.trim()}`)
    assert(!/^[>|]/.test(expr.trim()), `${name}: ${of} writes its ${where.split(' ')[1]} as a block scalar; keep it on one line so its contexts can be read`)
    const body = expr.trim().replace(/^\$\{\{/, '').replace(/\}\}$/, '')
    const bad = [...new Set(contextsIn(body))].filter((c) => !ALLOWED[where].has(c))
    assert(bad.length === 0, `${name}: ${of}'s ${where.split(' ')[1]} reads ${bad.join(', ')}, which GitHub does not allow there (only ${[...ALLOWED[where]].join(', ')}), so it refuses the whole file`)
  }
}
assert(restrictedRead.length > 0, 'the restricted-expression reader found nothing in any workflow; it is reading nothing')

/**
 * ⚠⚠ THE PLATFORMS CHECKED ARE THE PLATFORMS SHIPPED. source-checks keeps its own copy of the six legs (it has to:
 *    its matrix is chosen at run time), so the copy is compared with candidate.yml's matrix, os + label + family.
 */
const shippedLegs = [...candidate.matchAll(/- os: (\S+)\r?\n\s+label: (\S+)\r?\n\s+family: (\S+)/g)].map((m) => `${m[1]} ${m[2]} ${m[3]}`).sort()
const checkedJson = /all='(\[[\s\S]*?\])'/.exec(sourceChecks)
assert(checkedJson, 'source-checks states its legs as one JSON list')
const checkedLegs = JSON.parse(checkedJson[1]).map((l) => `${l.os} ${l.label} ${l.family}`).sort()
assert(shippedLegs.length === 6, `candidate.yml ships ${shippedLegs.length} legs as read here; expected the six`)
assert(JSON.stringify(checkedLegs) === JSON.stringify(shippedLegs), `the legs source-checks runs differ from the legs candidate.yml ships: checked [${checkedLegs.join('; ')}], shipped [${shippedLegs.join('; ')}]`)
console.log(`restricted expressions read (${restrictedRead.length}, across ${workflowFiles.length} workflows):`)
for (const r of restrictedRead) console.log(`  ${r}`)
console.log(`legs checked = legs shipped: ${checkedLegs.length}`)
assert(/SOURCE_REPO_TOKEN/.test(candidate) && /compare\/\$\{\{ inputs\.source_sha \}\}\.\.\.main/.test(candidate), 'candidate must verify private-source ancestry')
assert(/persisting credentials/.test(candidate) && /source\/package-lock\.json/.test(candidate), 'source must be fetched before source-controlled commands execute')
assert(!/GH_RELEASE_TOKEN|CLOUDFLARE_API_TOKEN/.test(candidate + promotion), 'controller must use no long-lived publishing or Cloudflare token')
const unprivilegedBuild = candidate.slice(candidate.indexOf('\n  build:'), candidate.indexOf('\n  draft:'))
assert(!/contents:\s*write/.test(unprivilegedBuild) && !/GH_TOKEN/.test(unprivilegedBuild), 'source build job must have no publishing authority')
assert(/\n  draft:[\s\S]*contents: write/.test(candidate), 'only the isolated draft job may create a release')
assert(/environment:.*public-beta/.test(promotion) && /PROMOTE \$\{\{ inputs\.tag \}\}/.test(promotion), 'promotion must use a protected environment and exact acknowledgement')
assert(/Get-AuthenticodeSignature/.test(candidate) && /codesign --verify/.test(candidate) && /stapler validate/.test(candidate), 'public beta must verify both platform trust chains')

// ONE channel list: both workflows offer exactly the channels scripts/channels.mjs defines, in any order.
const channelOptions = (workflow) => {
  const block = /\n      channel:\n[\s\S]*?options:\n((?:\s+- [a-z-]+\n)+)/.exec(workflow)
  return block ? block[1].trim().split(/\n/).map((l) => l.replace(/^\s*-\s*/, '').trim()).sort() : []
}
const defined = Object.keys(CHANNELS).sort()
assert(JSON.stringify(channelOptions(candidate)) === JSON.stringify(defined), `candidate channels ${channelOptions(candidate)} must equal ${defined}`)
assert(JSON.stringify(channelOptions(promotion)) === JSON.stringify(defined), `promotion channels ${channelOptions(promotion)} must equal ${defined}`)
/**
 * ⚠⚠ THE SIGNING TRUTH IS STATED IN THREE PLACES, SO ALL THREE ARE EVALUATED — never matched as text. The table
 *    (channels.mjs), the step that actually signs (its `if:` and the families its CSC_LINK has a secret for), and the
 *    verification record's `$signed` claim. The first cut of this check read the claim's TEXT, and a negative control
 *    that made the table sign nothing on mac-signed-beta stayed green: the fixtures below derive from the table too, so a
 *    table drifting from the workflow agreed with itself. Evaluating the workflow closes that.
 */
const families = ['windows', 'macos', 'linux']
const ghExpr = (expr, channel, family) =>
  Function(`return (${expr.replace(/inputs\.channel/g, JSON.stringify(channel)).replace(/matrix\.family/g, JSON.stringify(family)).replace(/(!?)==/g, (_m, bang) => (bang ? '!==' : '==='))})`)()
const stepIf = (name) => {
  const m = new RegExp(`- name: ${name}\\n\\s+if: (.+)\\n`).exec(candidate)
  assert(m, `the "${name}" step must exist with an if: condition`)
  return m[1]
}
const signedIf = stepIf('Package signed candidate')
const unsignedIf = stepIf('Package unsigned candidate')
const cscFamilies = [...candidate.matchAll(/matrix\.family == '([a-z]+)' && secrets\.[A-Z_]*CSC_LINK/g)].map((m) => m[1])
assert(cscFamilies.length > 0, 'the signed step names the families it has a certificate for')
const claimLine = /\$signed = (.+)\n/.exec(candidate)
assert(claimLine, 'the verification record states its signing claim')
const claimJs = claimLine[1]
  .replace(/\$env:RELEASE_CHANNEL -eq '([a-z-]+)'/g, (_m, v) => `(channel === '${v}')`)
  .replace(/\$env:RELEASE_FAMILY -in @\(([^)]*)\)/g, (_m, list) => `[${list}].includes(family)`)
  .replace(/\$env:RELEASE_FAMILY -eq '([a-z]+)'/g, (_m, v) => `(family === '${v}')`)
  .replace(/ -and /g, ' && ')
  .replace(/ -or /g, ' || ')
const claims = Function('channel', 'family', `return (${claimJs})`)
for (const channel of Object.keys(CHANNELS)) {
  for (const family of families) {
    const table = signedFor(channel, family)
    const step = ghExpr(signedIf, channel, family) && cscFamilies.includes(family)
    const claim = claims(channel, family) === true
    assert(table === step && step === claim, `${channel}/${family}: the table says ${table}, the signing step ${step}, the record ${claim}`)
    // …and every leg is packaged exactly once: by the signed step or by the unsigned one, never both, never neither.
    assert(ghExpr(signedIf, channel, family) !== ghExpr(unsignedIf, channel, family), `${channel}/${family} is packaged by ${ghExpr(signedIf, channel, family) ? 'both' : 'neither'} packaging step(s)`)
  }
}
// A signed mac leg on the mac-signed channel is VERIFIED: codesign + stapler run whenever a channel signs macOS.
assert(/Verify macOS signature and notarization ticket\n\s+if: inputs\.channel != 'internal-unsigned' && matrix\.family == 'macos'/.test(candidate), 'every channel that signs macOS verifies the trust chain')
assert(/if: inputs\.channel == 'mac-signed-beta'[\s\S]*?macos-arm64', 'macos-x64'/.test(promotion), 'promoting a mac-signed beta enforces the macOS signing boundary')

const sourceSha = '0123456789abcdef0123456789abcdef01234567'
const assets = {
  'windows-x64': 'clarity-aui-1.2.3-x64.exe',
  'windows-arm64': 'clarity-aui-1.2.3-arm64.exe',
  'macos-arm64': 'clarity-aui-1.2.3-arm64.dmg',
  'macos-x64': 'clarity-aui-1.2.3-x64.dmg',
  'linux-x64': 'clarity-aui-1.2.3-x86_64.AppImage',
  'linux-arm64': 'clarity-aui-1.2.3-arm64.AppImage'
}

for (const channel of Object.keys(CHANNELS)) {
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
        signed: signedFor(channel, platform.split('-')[0])
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
        writeFileSync(join(wrongArch, `verification-${platform}.json`), JSON.stringify({ schema: 1, platform, channel, source_sha: sourceSha, verified: true, signed: signedFor(channel, platform.split('-')[0]) }))
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

// A leg that CLAIMS a signature its channel does not grant is refused — the mac-signed beta must not pass off an
// unsigned Windows installer as signed, and must not pass off an unsigned mac one either.
for (const [channel, liar] of [['mac-signed-beta', 'windows-x64'], ['mac-signed-beta', 'macos-arm64'], ['internal-unsigned', 'macos-x64']]) {
  const directory = mkdtempSync(join(tmpdir(), 'clarity-release-claim-'))
  try {
    for (const [platform, name] of Object.entries(assets)) {
      writeFileSync(join(directory, name), `fixture-${channel}-${platform}`)
      const sha256 = createHash('sha256').update(readFileSync(join(directory, name))).digest('hex')
      writeFileSync(join(directory, `SHA256SUMS-${platform}.txt`), `${sha256}  ${name}\n`)
      const honest = signedFor(channel, platform.split('-')[0])
      writeFileSync(join(directory, `verification-${platform}.json`), JSON.stringify({ schema: 1, platform, channel, source_sha: sourceSha, verified: true, signed: platform === liar ? !honest : honest }))
    }
    const refused = spawnSync(process.execPath, [join(root, 'scripts', 'assemble-manifest.mjs'), directory, 'v1.2.3', sourceSha, channel, join(directory, 'm.json')]).status !== 0
    assert(refused, `a ${channel} leg (${liar}) with a false signing claim was assembled`)
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
}

/**
 * ⚠⚠⚠ THE MAC FEED MUST NAME BOTH ARCHITECTURES. Both macOS legs write `latest-mac.yml` and the draft job
 *     downloads every leg into one flat directory, so before the per-leg rename one mac feed silently overwrote
 *     the other and the release would have carried an update feed for a single architecture — the half of the
 *     Mac users on the other one would never see an update. The first all-six-green candidate (2026-09-21) was
 *     stopped by the name/hash collision rather than shipping that, which is the only reason it was noticed.
 *     These two cases pin the merge and, more importantly, pin its REFUSAL.
 */
const feed = (url) => `version: 1.2.3\nfiles:\n  - url: ${url}\n    sha512: deadbeef\n    size: 42\npath: ${url}\nsha512: deadbeef\nreleaseDate: '2026-09-21T00:00:00.000Z'\n`
const legFeeds = {
  'windows-x64': 'clarity-aui-1.2.3-x64.exe',
  'windows-arm64': 'clarity-aui-1.2.3-arm64.exe',
  'macos-arm64': 'clarity-aui-1.2.3-arm64.dmg',
  'macos-x64': 'clarity-aui-1.2.3-x64.dmg',
  'linux-x64': 'clarity-aui-1.2.3-x86_64.AppImage',
  'linux-arm64': 'clarity-aui-1.2.3-arm64.AppImage'
}
const mergeIn = (directory) =>
  spawnSync(process.execPath, [join(root, 'scripts', 'merge-update-feeds.mjs'), directory], { encoding: 'utf8' })

const feeds = mkdtempSync(join(tmpdir(), 'clarity-release-feeds-'))
try {
  for (const [leg, url] of Object.entries(legFeeds)) writeFileSync(join(feeds, `latest-${leg}.yml`), feed(url))
  assert(mergeIn(feeds).status === 0, 'the six per-leg feeds must merge')
  const mac = readFileSync(join(feeds, 'latest-mac.yml'), 'utf8')
  assert(mac.includes('-arm64.dmg') && mac.includes('-x64.dmg'), 'the merged mac feed must name BOTH architectures')
  const windows = readFileSync(join(feeds, 'latest.yml'), 'utf8')
  assert(windows.includes('-x64.exe') && windows.includes('-arm64.exe'), 'the merged windows feed must name BOTH architectures')
  // The rename would strand Linux under a name no AppImage client asks for, so the canonical pair must exist.
  readFileSync(join(feeds, 'latest-linux.yml'), 'utf8')
  readFileSync(join(feeds, 'latest-linux-arm64.yml'), 'utf8')
} finally {
  rmSync(feeds, { recursive: true, force: true })
}

const halfFeed = mkdtempSync(join(tmpdir(), 'clarity-release-halffeed-'))
try {
  // Both mac legs present, but the x64 leg carries the arm64 build — the shape a silent overwrite produces.
  for (const [leg, url] of Object.entries(legFeeds)) {
    writeFileSync(join(halfFeed, `latest-${leg}.yml`), feed(leg === 'macos-x64' ? legFeeds['macos-arm64'] : url))
  }
  assert(mergeIn(halfFeed).status !== 0, 'a mac feed that lost an architecture was accepted')
} finally {
  rmSync(halfFeed, { recursive: true, force: true })
}

console.log('PASS: controller workflow boundary, manifest tamper rejection and update-feed arch coverage verified')
