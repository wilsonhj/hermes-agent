import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readdirSync, readFileSync } from 'node:fs'

import { test } from 'vitest'

import {
  buildContentSecurityPolicy,
  CSP_BOOTSTRAP_SCRIPT_HASH,
  CSP_VITE_REACT_REFRESH_HASH,
  EMBED_FRAME_HOSTS,
  EMBED_SCRIPT_HOSTS,
  installContentSecurityPolicy,
  isAppDocumentUrl
} from './content-security-policy'

const REPO_INDEX_HTML = new URL('../index.html', import.meta.url)
const EMBEDS_DIR = new URL('../src/components/assistant-ui/embeds/', import.meta.url)

function sha256Base64(text: string): string {
  return `sha256-${createHash('sha256').update(text, 'utf8').digest('base64')}`
}

/** Sources listed for one directive of a policy string. */
function directive(policy: string, name: string): string[] {
  const found = policy
    .split(';')
    .map(part => part.trim())
    .find(part => part === name || part.startsWith(`${name} `))

  assert.ok(found, `policy is missing the ${name} directive`)

  return found.split(/\s+/).slice(1)
}

// ---------------------------------------------------------------------------
// The inline bootstrap hash must track index.html.

test('the bootstrap hash matches the inline theme script actually in index.html', () => {
  const html = readFileSync(REPO_INDEX_HTML, 'utf8')
  const inline = [...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g)]

  assert.equal(
    inline.length,
    1,
    'index.html should hold exactly one inline script (the theme bootstrap); every inline script needs its own hash in the policy'
  )

  assert.equal(
    sha256Base64(inline[0][1]),
    CSP_BOOTSTRAP_SCRIPT_HASH,
    'the inline theme bootstrap in index.html changed — regenerate CSP_BOOTSTRAP_SCRIPT_HASH, or every window boots white-flashing with a blocked inline script'
  )
})

test('the Vite Fast Refresh hash matches the preamble @vitejs/plugin-react injects', () => {
  // Captured verbatim from the running dev server (curl http://127.0.0.1:5174/).
  // A plugin upgrade that rewrites this preamble must land here too, or
  // `npm run dev` white-screens on a blocked inline script.
  const preamble = `import { injectIntoGlobalHook } from "/@react-refresh";
injectIntoGlobalHook(window);
window.$RefreshReg$ = () => {};
window.$RefreshSig$ = () => (type) => type;`

  assert.equal(sha256Base64(preamble), CSP_VITE_REACT_REFRESH_HASH)
})

test('index.html carries the development policy verbatim', () => {
  const html = readFileSync(REPO_INDEX_HTML, 'utf8')
  const meta = html.match(/<meta\s+http-equiv="Content-Security-Policy"\s+content="([^"]+)"/)

  assert.ok(meta, 'index.html has no Content-Security-Policy meta tag')
  // The static tag must be the SUPERSET policy: a second policy (the header the
  // main process adds) can only narrow it, so a stricter tag would break dev.
  assert.equal(meta[1], buildContentSecurityPolicy('development'))
})

// ---------------------------------------------------------------------------
// Policy contents.

test('production never allows eval or inline script', () => {
  const production = buildContentSecurityPolicy('production')
  const script = directive(production, 'script-src')

  assert.ok(!script.includes("'unsafe-eval'"), "script-src must not allow 'unsafe-eval'")
  assert.ok(!script.includes("'unsafe-inline'"), "script-src must not allow 'unsafe-inline'")
  assert.ok(!production.includes("'unsafe-eval'"), "no directive may allow 'unsafe-eval'")
})

test('production drops the dev-only Fast Refresh hash that development carries', () => {
  const production = directive(buildContentSecurityPolicy('production'), 'script-src')
  const development = directive(buildContentSecurityPolicy('development'), 'script-src')

  assert.ok(!production.includes(`'${CSP_VITE_REACT_REFRESH_HASH}'`))
  assert.ok(development.includes(`'${CSP_VITE_REACT_REFRESH_HASH}'`))
  // The Fast Refresh hash is the ONLY difference between the two modes.
  assert.deepEqual(
    development.filter(source => source !== `'${CSP_VITE_REACT_REFRESH_HASH}'`),
    production
  )
})

test('script-src keeps the two capabilities the app cannot run without', () => {
  const script = directive(buildContentSecurityPolicy('production'), 'script-src')

  // src/contrib/runtime-loader.ts import()s runtime plugins from a Blob URL.
  assert.ok(script.includes('blob:'))
  // Shiki's Oniguruma engine is WebAssembly; without this every code block,
  // diff and file preview loses highlighting.
  assert.ok(script.includes("'wasm-unsafe-eval'"))
  assert.ok(script.includes("'self'"))
  assert.ok(script.includes(`'${CSP_BOOTSTRAP_SCRIPT_HASH}'`))
})

test('the hardening directives are present and unwildcarded', () => {
  const policy = buildContentSecurityPolicy('production')

  assert.deepEqual(directive(policy, 'default-src'), ["'self'"])
  assert.deepEqual(directive(policy, 'object-src'), ["'none'"])
  assert.deepEqual(directive(policy, 'base-uri'), ["'self'"])
  assert.deepEqual(directive(policy, 'form-action'), ["'none'"])
  assert.ok(!/(^|[\s;])\*($|[\s;])/.test(policy), 'no directive may use a bare * source')
})

test('the renderer keeps the connectivity it actually uses', () => {
  const policy = buildContentSecurityPolicy('production')
  const connect = directive(policy, 'connect-src')

  // The gateway socket is opened straight from the renderer against a
  // user-configured host (local backend, LAN box, hosted gateway, SSH tunnel).
  assert.ok(connect.includes('ws:'))
  assert.ok(connect.includes('wss:'))
  // Local media streams through the custom hermes-media:// protocol.
  assert.ok(connect.includes('hermes-media:'))
  assert.ok(directive(policy, 'media-src').includes('hermes-media:'))
  assert.ok(directive(policy, 'img-src').includes('hermes-media:'))
  // Google-Fonts-backed theme presets (src/themes/presets.ts).
  assert.ok(directive(policy, 'style-src').includes('https://fonts.googleapis.com'))
  assert.ok(directive(policy, 'font-src').includes('https://fonts.gstatic.com'))
})

// ---------------------------------------------------------------------------
// Embed hosts: iframes are not script hosts.

test('embed iframe hosts live in frame-src and never in script-src', () => {
  const policy = buildContentSecurityPolicy('production')
  const frame = directive(policy, 'frame-src')
  const script = directive(policy, 'script-src')

  for (const host of EMBED_FRAME_HOSTS) {
    assert.ok(frame.includes(host), `${host} should be allowed as an iframe`)
  }

  for (const host of frame) {
    if (!EMBED_SCRIPT_HOSTS.includes(host)) {
      assert.ok(
        !script.includes(host),
        `${host} is an iframe host and must not be allowed to run script in the app document`
      )
    }
  }

  assert.deepEqual(EMBED_SCRIPT_HOSTS, ['https://platform.twitter.com', 'https://www.instagram.com'])

  for (const host of EMBED_SCRIPT_HOSTS) {
    assert.ok(script.includes(host))
  }
})

test('every provider embedUrl host is allowed as a frame', () => {
  const providersDir = new URL('providers/', EMBEDS_DIR)
  const hosts = new Set<string>()

  for (const file of readdirSync(providersDir)) {
    if (!file.endsWith('.ts') || file.endsWith('.test.ts')) {
      continue
    }

    const source = readFileSync(new URL(file, providersDir), 'utf8')

    for (const match of source.matchAll(/embedUrl:\s*[`'"]https:\/\/([a-z0-9.-]+)/gi)) {
      hosts.add(`https://${match[1]}`)
    }
  }

  // Sanity: the scan found providers at all (a rename must not silently pass).
  assert.ok(hosts.size >= 6, `expected several provider hosts, found ${[...hosts].join(', ')}`)

  for (const host of hosts) {
    assert.ok(EMBED_FRAME_HOSTS.includes(host), `${host} is built as an embed iframe URL but is missing from frame-src`)
  }
})

test('remote widget scripts are allowlisted only for the providers that run them', () => {
  const social = readFileSync(new URL('social-embed.tsx', EMBEDS_DIR), 'utf8')
  const tiktokProvider = readFileSync(new URL('providers/tiktok.ts', EMBEDS_DIR), 'utf8')
  const script = directive(buildContentSecurityPolicy('production'), 'script-src')

  assert.match(social, /src: 'https:\/\/platform\.twitter\.com\/widgets\.js'/)
  assert.match(social, /src: 'https:\/\/www\.instagram\.com\/embed\.js'/)

  // TikTok's entry in that table is dead code: providers/tiktok.ts resolves to
  // the iframe renderer, so url-embed.tsx never routes TikTok to the script
  // path. If that ever flips back, this fails — and www.tiktok.com then has to
  // be added to EMBED_SCRIPT_HOSTS.
  assert.match(tiktokProvider, /renderer: 'frame'/)
  assert.ok(!script.includes('https://www.tiktok.com'), 'TikTok is an iframe embed, not a script host')
})

test('negative fixtures from the embed detector are not allowlisted', () => {
  const policy = buildContentSecurityPolicy('production')

  // detect.test.ts uses these as URLs that must NOT resolve to an embed.
  assert.ok(!policy.includes('example.com'))
  assert.ok(!policy.includes('github.com'))
})

// ---------------------------------------------------------------------------
// Scoping: only the app's own document gets stamped.

test('isAppDocumentUrl matches the dev server document and nothing else', () => {
  const devServer = 'http://127.0.0.1:5174'

  assert.ok(isAppDocumentUrl(devServer, { devServer }))
  assert.ok(isAppDocumentUrl(`${devServer}/`, { devServer }))
  assert.ok(isAppDocumentUrl(`${devServer}/?win=secondary#/abc`, { devServer }))
  assert.ok(isAppDocumentUrl(`${devServer}/?win=overlay#/`, { devServer }))

  assert.ok(!isAppDocumentUrl('http://127.0.0.1:5174.evil.test/', { devServer }))
  assert.ok(!isAppDocumentUrl('https://www.youtube-nocookie.com/embed/x', { devServer }))
  assert.ok(!isAppDocumentUrl('file:///home/user/app/dist/index.html', { devServer }))
})

test('isAppDocumentUrl matches the packaged index and no other local file', () => {
  const rendererIndexUrl = 'file:///opt/Hermes/resources/app/dist/index.html'

  assert.ok(isAppDocumentUrl(rendererIndexUrl, { rendererIndexUrl }))
  assert.ok(isAppDocumentUrl(`${rendererIndexUrl}?win=overlay#/`, { rendererIndexUrl }))
  assert.ok(isAppDocumentUrl(`${rendererIndexUrl}#/session-1`, { rendererIndexUrl }))

  // A user's own HTML rendered in the preview pane, or any other local file,
  // must keep whatever policy it ships with.
  assert.ok(!isAppDocumentUrl('file:///home/user/project/index.html', { rendererIndexUrl }))
  assert.ok(!isAppDocumentUrl('file:///opt/Hermes/resources/app/dist/index.html.bak', { rendererIndexUrl }))
  assert.ok(!isAppDocumentUrl('', { rendererIndexUrl }))
  assert.ok(!isAppDocumentUrl('file:///opt/Hermes/resources/app/dist/index.html', {}))
})

// ---------------------------------------------------------------------------
// Installation behaviour.

function fakeSession() {
  const handlers: any[] = []

  return {
    handlers,
    webRequest: {
      onHeadersReceived(handler) {
        handlers.push(handler)
      }
    }
  }
}

function headersFor(sess, details) {
  let result

  sess.handlers[0](details, value => {
    result = value
  })

  return result.responseHeaders
}

test('installContentSecurityPolicy stamps the app document only', () => {
  const sess = fakeSession()
  const rendererIndexUrl = 'file:///opt/Hermes/dist/index.html'

  assert.equal(installContentSecurityPolicy(sess, { mode: 'production', rendererIndexUrl }), true)
  assert.equal(sess.handlers.length, 1)

  const stamped = headersFor(sess, {
    resourceType: 'mainFrame',
    url: rendererIndexUrl,
    responseHeaders: { 'content-type': ['text/html'] }
  })

  assert.deepEqual(stamped['Content-Security-Policy'], [buildContentSecurityPolicy('production')])
  assert.deepEqual(stamped['content-type'], ['text/html'])

  // An embed iframe keeps the policy its own origin serves — overriding it with
  // ours would break the embed.
  const embed = headersFor(sess, {
    resourceType: 'subFrame',
    url: 'https://open.spotify.com/embed/track/1',
    responseHeaders: { 'content-security-policy': ["default-src 'self' spotify.com"] }
  })

  assert.deepEqual(embed['content-security-policy'], ["default-src 'self' spotify.com"])
  assert.equal(embed['Content-Security-Policy'], undefined)

  // Another main-frame document in the same session (OAuth login window, a
  // previewed local file) is left alone too.
  const other = headersFor(sess, {
    resourceType: 'mainFrame',
    url: 'https://portal.nousresearch.com/login',
    responseHeaders: {}
  })

  assert.equal(other['Content-Security-Policy'], undefined)
})

test('installContentSecurityPolicy replaces any policy already on the app document', () => {
  const sess = fakeSession()
  const devServer = 'http://127.0.0.1:5174'

  installContentSecurityPolicy(sess, { mode: 'development', devServer })

  const stamped = headersFor(sess, {
    resourceType: 'mainFrame',
    url: `${devServer}/`,
    responseHeaders: {
      'content-security-policy': ["script-src 'none'"],
      'Content-Security-Policy-Report-Only': ["script-src 'none'"]
    }
  })

  assert.deepEqual(Object.keys(stamped), ['Content-Security-Policy'])
  assert.deepEqual(stamped['Content-Security-Policy'], [buildContentSecurityPolicy('development')])
})

test('installContentSecurityPolicy is a no-op without a webRequest surface', () => {
  assert.equal(installContentSecurityPolicy(null, {}), false)
  assert.equal(installContentSecurityPolicy({}, {}), false)
})

test('main.ts installs the policy with the dev-server / packaged-file split', () => {
  const main = readFileSync(new URL('./main.ts', import.meta.url), 'utf8')

  assert.match(main, /import \{ installContentSecurityPolicy \} from '\.\/content-security-policy'/)
  assert.match(main, /installContentSecurityPolicy\(session\.defaultSession, \{/)
  assert.match(main, /mode: DEV_SERVER \? 'development' : 'production'/)
  assert.match(main, /rendererIndexUrl: DEV_SERVER \? null : pathToFileURL\(resolveRendererIndex\(\)\)\.toString\(\)/)
})
