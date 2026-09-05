// Secondary "session windows" — one extra OS window per chat so a user can
// work with multiple chats side by side. The pure, Electron-free pieces live
// here so they can be unit-tested with node --test (mirroring how the rest of
// electron/*.ts splits testable logic out of the main.ts monolith).

import { fileURLToPath, pathToFileURL } from 'node:url'

import { sensitiveFileBlockReason } from './hardening'

// Secondary windows open at the minimum usable size — a compact side panel for
// subagent watch / cmd-click session pop-out, not a second full desktop.
const SESSION_WINDOW_MIN_WIDTH = 420
const SESSION_WINDOW_MIN_HEIGHT = 620

// Shared webPreferences for every window that renders the chat transcript — the
// primary window AND the secondary session windows. Keeping it in one place is
// the whole point: the two BrowserWindow definitions in main.ts used to be
// hand-copied, and the secondary windows silently lost `backgroundThrottling:
// false`, so a streamed answer stalled until the window regained focus.
//
// `backgroundThrottling: false` is load-bearing: the transcript streams to the
// screen through a requestAnimationFrame-gated flush, which Chromium pauses for
// blurred/occluded windows. A streaming chat app must keep painting in the
// background, so every chat window opts out. The preload path is injected
// because it depends on the Electron entry's __dirname.
//
// `webviewTag: true` is also load-bearing: the right-rail preview pane mounts a
// <webview> (src/app/chat/right-rail/preview-pane.tsx) to render dev-server URLs
// and local HTML out-of-process. It is NOT free, though — see
// sanitizeWebviewAttach below, which every attach must go through.
function chatWindowWebPreferences(preloadPath: string) {
  return {
    preload: preloadPath,
    contextIsolation: true,
    webviewTag: true,
    sandbox: true,
    nodeIntegration: false,
    devTools: true,
    backgroundThrottling: false
  }
}

// A <webview> is renderer-authored markup, and its `preload` / `nodeintegration`
// attributes are honoured by the MAIN process, not the renderer. So the chat
// window's own hardening (contextIsolation + sandbox + nodeIntegration:false)
// buys nothing on its own: anything that can inject DOM into the transcript —
// a malicious tool result, a prompt-injected model response, an XSS in rendered
// markdown — could attach a guest with Node enabled, or point one at our preload
// and inherit the whole desktop bridge (terminal spawn, fs read/write, git,
// openExternal). Every attach is therefore scrubbed in the main process, where
// the renderer can't reach it.
//
// The preview pane only ever loads http(s) dev servers or `file://` HTML
// (src/lib/local-preview.ts builds both), so anything else — `javascript:`,
// `data:`, a custom protocol — is a guest we never meant to open.
const WEBVIEW_ALLOWED_PROTOCOLS = new Set(['file:', 'http:', 'https:'])

function isAllowedWebviewSrc(src) {
  if (typeof src !== 'string' || !src.trim()) {
    return false
  }

  try {
    const parsed = new URL(src)

    if (!WEBVIEW_ALLOWED_PROTOCOLS.has(parsed.protocol)) {
      return false
    }

    if (parsed.protocol === 'file:') {
      let filePath

      try {
        filePath = fileURLToPath(parsed)
      } catch {
        return false
      }

      return sensitiveFileBlockReason(filePath) == null
    }

    return true
  } catch {
    return false
  }
}

// Scrub a pending <webview> attach. Electron reads `webPreferences`/`params`
// back after the will-attach-webview handler returns, so this mutates them in
// place; the return value says whether the attach may proceed at all. Node
// access is stripped unconditionally rather than only for rejected sources, so
// an allowed-looking src still can't smuggle in the preload bridge.
function sanitizeWebviewAttach(webPreferences: any = {}, params: any = {}) {
  delete webPreferences.preload
  delete webPreferences.preloadURL
  webPreferences.nodeIntegration = false
  webPreferences.nodeIntegrationInSubFrames = false
  webPreferences.nodeIntegrationInWorker = false
  webPreferences.contextIsolation = true
  webPreferences.sandbox = true
  webPreferences.webSecurity = true

  // The element attributes are what Electron re-parses for the guest, so the
  // Node-granting ones have to go too — clearing webPreferences alone is not
  // enough. `allowpopups` goes because a guest popup is a fresh WebContents we
  // never asked for.
  delete params.preload
  delete params.nodeintegration
  delete params.nodeintegrationinsubframes
  delete params.nodeintegrationinworker
  delete params.allowpopups
  delete params.disablewebsecurity
  delete params.webpreferences

  return isAllowedWebviewSrc(params.src)
}

// Build the renderer URL for a secondary window. The renderer uses a
// HashRouter, so the session route lives after the '#'. The `?win=secondary`
// flag MUST sit in the query string BEFORE the '#': anything after the '#' is
// treated as the route by HashRouter and would break routeSessionId(). The
// renderer reads the flag from window.location.search to suppress the install /
// onboarding overlays and the global session sidebar. `watch=1` marks a
// spectator window (e.g. a running subagent's session): the renderer resumes it
// lazily so the gateway never builds an agent just to stream into it.
function buildSessionWindowUrl(sessionId: string, { devServer, rendererIndexPath, watch }: any = {}) {
  const query = `?win=secondary${watch ? '&watch=1' : ''}`
  const route = `#/${encodeURIComponent(sessionId)}`

  if (devServer) {
    const base = devServer.endsWith('/') ? devServer.slice(0, -1) : devServer

    return `${base}/${query}${route}`
  }

  return `${pathToFileURL(rendererIndexPath).toString()}${query}${route}`
}

// Full "instance" windows (⌘⇧N / the "New Window" command) open a complete app
// peer, not a compact chat. Cascade each one off its source window's bounds so a
// new window doesn't land exactly on top of the one it was spawned from. Pure so
// it's unit-testable; the Electron glue (reading the focused window's bounds,
// constructing the BrowserWindow) stays in main.ts. `base` is the source
// window's current bounds, or null when there's no live source window — then the
// persisted primary geometry (`fallback`) is used as-is.
const INSTANCE_CASCADE_OFFSET = 32

function instanceWindowBounds(base: { x: number; y: number; width: number; height: number } | null, fallback: any) {
  if (!base) {
    return fallback
  }

  return {
    width: base.width,
    height: base.height,
    x: base.x + INSTANCE_CASCADE_OFFSET,
    y: base.y + INSTANCE_CASCADE_OFFSET
  }
}

// A small registry keyed by sessionId that guarantees one window per chat:
// opening a session that already has a live window focuses it instead of
// spawning a duplicate, and a window removes itself from the registry when it
// closes. The actual BrowserWindow construction is injected (the `factory`) so
// this module stays free of Electron and is unit-testable.
function createSessionWindowRegistry() {
  const windows = new Map()

  function openOrFocus(sessionId, factory) {
    const key = typeof sessionId === 'string' ? sessionId.trim() : ''

    if (!key) {
      return null
    }

    const existing = windows.get(key)

    if (existing && !existing.isDestroyed()) {
      // Focus-or-create: never duplicate a window for the same chat.
      if (typeof existing.isMinimized === 'function' && existing.isMinimized()) {
        existing.restore?.()
      }

      if (typeof existing.isVisible === 'function' && !existing.isVisible()) {
        existing.show?.()
      }

      existing.focus?.()

      return existing
    }

    const win = factory(key)

    if (!win) {
      return null
    }

    windows.set(key, win)

    // Self-cleanup on close so the registry never holds a destroyed window.
    win.on?.('closed', () => {
      if (windows.get(key) === win) {
        windows.delete(key)
      }
    })

    return win
  }

  return {
    openOrFocus,
    get: key => windows.get(key),
    has: key => windows.has(key),
    get size() {
      return windows.size
    }
  }
}

export {
  buildSessionWindowUrl,
  chatWindowWebPreferences,
  createSessionWindowRegistry,
  instanceWindowBounds,
  isAllowedWebviewSrc,
  sanitizeWebviewAttach,
  SESSION_WINDOW_MIN_HEIGHT,
  SESSION_WINDOW_MIN_WIDTH
}
