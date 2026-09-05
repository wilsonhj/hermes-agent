// Content-Security-Policy for the renderer.
//
// Why this exists: the transcript renders MODEL OUTPUT, and that document also
// holds the `hermesDesktop` preload bridge — terminal spawn, fs read/write, git,
// openExternal — so any script that runs there runs with the desktop's full IPC
// reach. Rich embeds load as cross-origin iframes (frame-src), never as scripts
// in this document. Before this module there was no CSP at all.
//
// DELIVERY (two layers, both needed):
//
//   1. `<meta http-equiv="Content-Security-Policy">` in index.html. Static, so
//      it is present for EVERY window (primary, session, instance, pet overlay)
//      and for both load paths — the dev server in `npm run dev` and the
//      packaged `file://` index. It carries the DEVELOPMENT policy, because a
//      static tag cannot vary by mode and must not break `npm run dev`.
//   2. This module's `installContentSecurityPolicy()`, which stamps the
//      mode-correct policy onto the app document's response headers from the
//      main process. Verified empirically on Electron 40: `onHeadersReceived`
//      DOES fire for `file://` main-frame loads and a CSP header set there IS
//      enforced, so production genuinely gets the production policy.
//
// Two policies on one document are intersected by the browser — a header can
// only ever NARROW the meta tag, never widen it. That is exactly the property
// this design leans on: the meta is the permissive superset (development), the
// header narrows it to `production` in a packaged build, and if the main-process
// wiring ever regresses the app degrades to the still-strict meta rather than to
// no policy at all.
//
// The ONLY difference between the two modes is the inline-script hash Vite's
// React Fast Refresh preamble needs (see CSP_VITE_REACT_REFRESH_HASH).

/**
 * Hash of the inline theme bootstrap in apps/desktop/index.html — the pre-paint
 * script that reads the persisted theme so a new window doesn't flash white.
 * It has to stay inline (it must run before the bundle), so the policy names it
 * by hash instead of allowing inline script wholesale.
 *
 * MAINTENANCE: this hash is over the EXACT text of that <script> element. Edit
 * the bootstrap — even a comment or one space — and this must be regenerated,
 * or every window boots white-flashing with a console CSP error.
 * `content-security-policy.test.ts` recomputes it from index.html and fails
 * loudly when the two drift, so the test failure is the reminder. To refresh:
 *   node -e "const fs=require('fs'),c=require('crypto');const h=fs.readFileSync('index.html','utf8');
 *   const m=h.match(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/);
 *   console.log('sha256-'+c.createHash('sha256').update(m[1],'utf8').digest('base64'))"
 */
const CSP_BOOTSTRAP_SCRIPT_HASH = 'sha256-thP3Xi4D3xLhY5XYiK6vCmNBel4nusdd7+E9sSYH7cI='

/**
 * Hash of the React Fast Refresh preamble that @vitejs/plugin-react injects
 * inline into index.html — DEV SERVER ONLY (verified by curling the running
 * dev server; the production build contains no such script). Without it
 * `npm run dev` white-screens on a blocked inline script.
 *
 * MAINTENANCE: it is @vitejs/plugin-react's text, so a plugin upgrade can
 * change it. The test pins the exact source string it hashes, so an upgrade
 * fails the test with the string to update rather than silently breaking dev.
 * Harmless in production: a hash only ever permits that one script body, and
 * that body just imports `/@react-refresh`, which does not exist in a build.
 */
const CSP_VITE_REACT_REFRESH_HASH = 'sha256-Z2/iFzh9VMlVkEOar1f/oSHWwQk3ve1qk/C2WdsC4Xk='

// Hosts loaded as IFRAMES (frame-src). These execute in their own origin, not
// ours, so listing them grants no access to the bridge. Sourced from the
// `embedUrl` each provider actually builds in
// src/components/assistant-ui/embeds/providers/ — NOT from the URL patterns
// those providers merely match on (youtu.be, m.youtube.com, twitter.com,
// fr.pinterest.com, vimeo.com … are inputs, never frame targets), and NOT from
// the negative fixtures in detect.test.ts (example.com, github.com).
// Twitter and Instagram used to inject widgets.js / embed.js into this
// document; they now use official iframes only, so they stay off script-src.
const EMBED_FRAME_HOSTS = [
  // providers/youtube.ts builds a youtube-nocookie.com/embed URL; www.youtube.com
  // is listed because YouTube redirects the privacy-enhanced player there in some
  // regions/consent flows and CSP re-checks every redirect hop.
  'https://www.youtube-nocookie.com',
  'https://www.youtube.com',
  // providers/vimeo.ts
  'https://player.vimeo.com',
  // providers/instagram.ts (www.instagram.com/<type>/<code>/embed)
  'https://www.instagram.com',
  // providers/pinterest.ts
  'https://assets.pinterest.com',
  // providers/tiktok.ts (www.tiktok.com/player/v1/<id>)
  'https://www.tiktok.com',
  // providers/spotify.ts
  'https://open.spotify.com',
  // providers/maps.ts builds maps.google.com/maps?output=embed, which redirects
  // to www.google.com/maps/embed — both hops need to be allowed.
  'https://maps.google.com',
  'https://www.google.com',
  // providers/maps.ts (OpenStreetMap export/embed.html)
  'https://www.openstreetmap.org',
  // providers/twitter.ts (platform.twitter.com/embed/Tweet.html)
  'https://platform.twitter.com',
  'https://syndication.twitter.com'
]

// Google Fonts: three theme presets in src/themes/presets.ts carry a `fontUrl`
// that themes/context.tsx injects as <link rel="stylesheet">. The stylesheet is
// served by fonts.googleapis.com and its @font-face files by fonts.gstatic.com.
const GOOGLE_FONTS_STYLESHEET = 'https://fonts.googleapis.com'
const GOOGLE_FONTS_FILES = 'https://fonts.gstatic.com'

type CspMode = 'development' | 'production'

/**
 * Build the policy string for a mode. `development` differs from `production`
 * by exactly one source: the Vite Fast Refresh preamble hash.
 */
function buildContentSecurityPolicy(mode: CspMode = 'production'): string {
  const scriptHashes = [CSP_BOOTSTRAP_SCRIPT_HASH]

  if (mode === 'development') {
    scriptHashes.push(CSP_VITE_REACT_REFRESH_HASH)
  }

  const directives: [string, string[]][] = [
    // Fallback for anything not named below (manifest-src, prefetch-src, …).
    ['default-src', ["'self'"]],
    // No <base> rewriting of every relative URL in the document.
    ['base-uri', ["'self'"]],
    // No <object>/<embed>/<applet> — the app uses none, and they are a classic
    // plugin-execution bypass.
    ['object-src', ["'none'"]],
    // Every form in the app is a React onSubmit handler; nothing posts to a
    // URL. Blocking form navigation removes a form-POST exfiltration path that
    // `connect-src` cannot cover.
    ['form-action', ["'none'"]],
    [
      'script-src',
      [
        // The app bundle. Verified on Electron 40: 'self' matches sibling
        // file:// scripts, so the packaged build loads dist/assets/*.js.
        "'self'",
        // src/contrib/runtime-loader.ts evaluates runtime plugins by
        // `import()`ing a Blob URL, and installs the SDK shim the same way.
        // Without blob: the whole plugin system stops loading.
        'blob:',
        // Shiki's Oniguruma regex engine is WebAssembly; Chromium refuses
        // WebAssembly.instantiate() under a CSP that lacks this. Dropping it
        // kills ALL syntax highlighting (transcript code blocks, diffs, file
        // preview). It permits wasm compilation only — NOT eval() of JS.
        "'wasm-unsafe-eval'",
        // CSP hash sources are keyword-quoted, e.g. 'sha256-…'.
        ...scriptHashes.map(hash => `'${hash}'`)
      ]
    ],
    [
      'style-src',
      [
        "'self'",
        // Required, not lazy: Vite injects dev CSS as <style> elements, mermaid
        // and the shiki/embed renderers inject <style>, and third-party widget
        // scripts style their own placeholders. There is no nonce plumbing for
        // a static file:// document. Style injection cannot reach the bridge.
        "'unsafe-inline'",
        GOOGLE_FONTS_STYLESHEET
      ]
    ],
    ['font-src', ["'self'", 'data:', GOOGLE_FONTS_FILES]],
    [
      'img-src',
      [
        "'self'",
        // data: — pet thumbs and gateway media arrive as data URIs; blob: —
        // generated/downloaded images; hermes-media: — the local media
        // streaming protocol registered in main.ts.
        'data:',
        'blob:',
        'hermes-media:',
        // Markdown from the model renders arbitrary <img src> (MarkdownImage in
        // markdown-text.tsx), and embed widgets pull their own thumbnails.
        // Restricting image hosts would break normal chat output; images cannot
        // execute, so the allowance is cheap.
        'https:',
        'http:'
      ]
    ],
    ['media-src', ["'self'", 'data:', 'blob:', 'hermes-media:', 'https:', 'http:']],
    [
      'connect-src',
      [
        "'self'",
        'data:',
        'blob:',
        'hermes-media:',
        // The gateway host is USER-CONFIGURED (local backend on a random
        // loopback port, a LAN box, a hosted gateway, or an SSH-forwarded
        // remote), and src/hermes.ts opens its JSON-RPC socket DIRECTLY from
        // the renderer — so ws:/wss: cannot be pinned to a host without
        // bricking the app. http(s) covers the renderer's remaining direct
        // fetches (image-download fallback) and Vite's dev-server requests.
        'https:',
        'http:',
        'ws:',
        'wss:'
      ]
    ],
    // The embed allowlist. Everything else — including anything the model can
    // name — is refused. Verified empirically: <webview> guests (the right-rail
    // preview pane, partition persist:hermes-preview) are NOT governed by
    // frame-src, so tightening this does not touch the preview pane.
    ['frame-src', EMBED_FRAME_HOSTS],
    // Bundled libraries spin workers up from blob URLs.
    ['worker-src', ["'self'", 'blob:']]
  ]

  // frame-ancestors is deliberately absent: it is ignored when delivered via
  // <meta> (and logs a console warning for every window), and an Electron app
  // document cannot be framed by a third party anyway.
  return directives.map(([name, sources]) => `${name} ${sources.join(' ')}`).join('; ')
}

/**
 * True when `url` is the app's OWN document — the only response that should be
 * stamped with this policy.
 *
 * Scope matters: `session.defaultSession` also carries the embed iframes and
 * any webview attached without a partition. Stamping the app's policy on a
 * YouTube or Spotify frame would override the policy THEY ship and break the
 * embed; stamping it on a previewed local HTML file would break the preview
 * pane. Only the top-level app document is matched.
 */
function isAppDocumentUrl(
  url: string,
  { devServer, rendererIndexUrl }: { devServer?: null | string; rendererIndexUrl?: null | string } = {}
): boolean {
  if (typeof url !== 'string' || !url) {
    return false
  }

  if (devServer) {
    const base = devServer.endsWith('/') ? devServer.slice(0, -1) : devServer

    // `${base}/?win=overlay#/`, `${base}/?win=secondary#/<id>`, or bare `${base}`.
    return url === base || url.startsWith(`${base}/`)
  }

  if (!rendererIndexUrl) {
    return false
  }

  // The packaged index, with or without the ?win=… query and hash route.
  return url === rendererIndexUrl || url.startsWith(`${rendererIndexUrl}?`) || url.startsWith(`${rendererIndexUrl}#`)
}

/**
 * Stamp the policy onto the app document's response headers.
 *
 * Replaces any Content-Security-Policy the response already carries (a dev
 * server or a file:// synthesised response carries none) and drops
 * report-only variants so a stale header can't confuse the enforced one.
 */
function installContentSecurityPolicy(
  targetSession,
  {
    mode = 'production',
    devServer = null,
    rendererIndexUrl = null
  }: { mode?: CspMode; devServer?: null | string; rendererIndexUrl?: null | string } = {}
): boolean {
  if (!targetSession?.webRequest?.onHeadersReceived) {
    return false
  }

  const policy = buildContentSecurityPolicy(mode)

  targetSession.webRequest.onHeadersReceived((details, callback) => {
    if (details.resourceType !== 'mainFrame' || !isAppDocumentUrl(details.url, { devServer, rendererIndexUrl })) {
      callback({ responseHeaders: details.responseHeaders })

      return
    }

    const headers = { ...(details.responseHeaders || {}) }

    for (const key of Object.keys(headers)) {
      if (/^content-security-policy(-report-only)?$/i.test(key)) {
        delete headers[key]
      }
    }

    headers['Content-Security-Policy'] = [policy]

    callback({ responseHeaders: headers })
  })

  return true
}

export {
  buildContentSecurityPolicy,
  CSP_BOOTSTRAP_SCRIPT_HASH,
  CSP_VITE_REACT_REFRESH_HASH,
  EMBED_FRAME_HOSTS,
  installContentSecurityPolicy,
  isAppDocumentUrl
}
