import path from 'node:path'

// Which local files `openExternalUrl` (main.ts) may hand to `shell.openPath`.
//
// Why this exists: `shell.openPath` dispatches to the OS file association, so
// opening a `.command` / `.desktop` / `.bat` / `.sh` / `.app` RUNS it. That path
// is reachable from model output — a markdown link of the form
// `[Q3 report.pdf](#media:/path/to/x.command)` renders through
// `src/components/assistant-ui/markdown-text.tsx` into `MediaAttachment`, whose
// non-image/audio/video branch is an anchor calling
// `openExternalLink(mediaExternalUrl(path))` → `file://…` → `shell.openPath`.
//
// SCOPE: this is UI deception / defense in depth, NOT a sandbox escape. The file
// has to already exist on disk, and under the default local backend the agent
// can run a shell anyway. What this closes is the mismatch where a click that
// reads as "open a document" silently executes a program instead.
//
// ALLOWLIST, not blocklist: the set of executable extensions is unbounded across
// platforms (.command .desktop .bat .cmd .com .exe .scr .ps1 .sh .app .vbs .jar
// .msi .lnk .pif .wsf …) and a blocklist will always miss one. The same call is
// already made one layer over for `hermes-media://` (STREAMABLE_MEDIA_EXTS in
// main.ts), and this mirrors that idiom rather than inventing a second mechanism.

/**
 * Media the app itself renders or streams — mirrors `MEDIA_MIME_TYPES` and
 * `STREAMABLE_MEDIA_EXTS` in main.ts plus the inert raster formats a user's own
 * photos arrive as. All are content the renderer would happily show inline, so
 * handing them to the OS viewer adds no capability.
 */
const OPENABLE_MEDIA_EXTS = [
  '.avi',
  '.avif',
  '.bmp',
  '.flac',
  '.gif',
  '.heic',
  '.ico',
  '.jpeg',
  '.jpg',
  '.m4a',
  '.mkv',
  '.mov',
  '.mp3',
  '.mp4',
  '.ogg',
  '.opus',
  '.png',
  '.tif',
  '.tiff',
  '.wav',
  '.webm',
  '.webp'
]

/**
 * Documents an agent plausibly produces and a user plausibly wants in a real
 * app rather than the in-app preview.
 *
 * Deliberately EXCLUDED, and why:
 *   - Source/script files (.js .py .rb .sh .ps1 …). `.js` runs under Windows
 *     Script Host and `.py` runs under a registered interpreter, so "open in my
 *     editor" is not what the OS necessarily does. The app already has an
 *     in-app text preview (`hermes:readFileText`) for reading these.
 *   - Local HTML/SVG (.htm .html .svg). A browser will execute script in them;
 *     `openPreviewInBrowser` is the dedicated path that re-allows HTML only.
 *   - Macro-enabled Office formats (.docm .xlsm .pptm .dotm …), which exist
 *     specifically to carry code.
 *   - Archives and disk images (.zip .dmg .iso …), which are mount/extract
 *     actions rather than "view this document".
 */
const OPENABLE_DOCUMENT_EXTS = [
  '.csv',
  '.doc',
  '.docx',
  '.epub',
  '.json',
  '.log',
  '.markdown',
  '.md',
  '.odp',
  '.ods',
  '.odt',
  '.pdf',
  '.ppt',
  '.pptx',
  '.rtf',
  '.tsv',
  '.txt',
  '.xls',
  '.xlsx',
  '.xml',
  '.yaml',
  '.yml'
]

/** Every extension `openExternalUrl` will hand to `shell.openPath`, lowercase. */
export const EXTERNALLY_OPENABLE_EXTS = new Set([...OPENABLE_MEDIA_EXTS, ...OPENABLE_DOCUMENT_EXTS])

/**
 * True when `filePath` may be handed to `shell.openPath`.
 *
 * Matching uses `path.extname`, which returns the LAST extension — so the
 * `report.pdf.command` disguise is judged on `.command` (what the OS actually
 * dispatches on), not on the `.pdf` a user's eye stops at.
 *
 * A PLAINLY NAMED DIRECTORY is allowed — opening a folder in the file manager
 * is a normal, non-executing action. The caller passes `isDirectory` rather
 * than this module touching fs, so the decision stays pure and testable.
 *
 * But "it's a directory" is NOT on its own sufficient: on macOS a bundle
 * (`.app`, `.bundle`, `.pkg`, `.workflow`, `.prefPane`, …) is also a directory,
 * and `shell.openPath` on one LAUNCHES it. Rather than enumerate bundle types —
 * the same losing game as blocklisting executables — a directory qualifies only
 * when it has NO extension at all. Every bundle type, present and future, is
 * excluded by construction. A dotted folder name degrades to reveal-in-folder,
 * and the dedicated `fs:openDir` IPC (used by the plugins door) is a separate
 * handler that this gate does not sit in front of.
 *
 * EXTENSIONLESS FILES ARE REJECTED. On macOS and Linux an extensionless file
 * with the exec bit set is directly runnable, and nothing the app itself
 * produces lacks an extension — so there is no legitimate case to trade for the
 * risk. Callers reveal these in the file manager instead.
 */
export function isExternallyOpenablePath(filePath: string, options: { isDirectory?: boolean } = {}): boolean {
  const raw = String(filePath || '')

  if (!raw) {
    return false
  }

  const ext = path.extname(raw).toLowerCase()

  if (options.isDirectory) {
    return ext === ''
  }

  return EXTERNALLY_OPENABLE_EXTS.has(ext)
}

/**
 * Extra extensions `openPreviewInBrowser` may hand to `shell.openExternal`.
 * `.html`/`.htm` are the preview pane's whole point, but they stay off the
 * `openPath` allowlist: a browser will execute script in a local HTML file.
 */
const PREVIEW_IN_BROWSER_EXTS = new Set(['.htm', '.html'])

/**
 * True when `filePath` may be handed to `shell.openExternal` as a `file:` URL
 * from the preview-in-browser path. Same gate as `isExternallyOpenablePath`,
 * plus `.html`/`.htm`. Executables, bundles, and extensionless files stay out.
 */
export function isPreviewInBrowserOpenablePath(
  filePath: string,
  options: { isDirectory?: boolean } = {}
): boolean {
  if (isExternallyOpenablePath(filePath, options)) {
    return true
  }

  if (options.isDirectory) {
    return false
  }

  const ext = path.extname(String(filePath || '')).toLowerCase()

  return PREVIEW_IN_BROWSER_EXTS.has(ext)
}
