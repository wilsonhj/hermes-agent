import fs from 'node:fs'
import path from 'node:path'

import { errorCode } from './error-narrowing'
import { resolveDirectoryForIpc } from './hardening'
import { resolveLocalReadPath } from './wsl-path-bridge'

// The dirent shape this module relies on. `isDirectory`/`isFile`/
// `isSymbolicLink` are optional because every use site probes with
// `typeof … === 'function'` first — injected stubs need not supply them.
interface ReadDirDirent {
  name: string
  isDirectory?: () => boolean
  isFile?: () => boolean
  isSymbolicLink?: () => boolean
}

interface ReadDirEntry {
  name: string
  path: string
  isDirectory: boolean
}

// The `node:fs` slice this module reaches for. `realpath`/`stat` are optional
// because callers legitimately inject partial stubs covering only the code path
// they exercise; a missing member throws inside an existing try/catch and is
// reported as a read-error, exactly as before.
interface ReadDirFs {
  promises: {
    readdir: (dirPath: string, options: { withFileTypes: true }) => Promise<ReadDirDirent[]>
    realpath?: ((statPath: string) => Promise<string>) | undefined
    stat?: ((statPath: string) => Promise<{ isDirectory: () => boolean }>) | undefined
  }
}

const FS_READDIR_STAT_CONCURRENCY = 16

// Always-hidden noise (covers non-git projects too; gitignore catches many of
// these, but the project tree should keep the same hygiene without one).
const FS_READDIR_HIDDEN = new Set([
  '.git',
  '.hg',
  '.svn',
  '.cache',
  '.next',
  '.turbo',
  '.venv',
  '__pycache__',
  'build',
  'dist',
  'node_modules',
  'target',
  'venv'
])

function direntIsDirectory(dirent: ReadDirDirent): boolean {
  return typeof dirent.isDirectory === 'function' && dirent.isDirectory()
}

function direntIsFile(dirent: ReadDirDirent): boolean {
  return typeof dirent.isFile === 'function' && dirent.isFile()
}

function direntIsSymbolicLink(dirent: ReadDirDirent): boolean {
  return typeof dirent.isSymbolicLink === 'function' && dirent.isSymbolicLink()
}

function shouldStatDirent(dirent: ReadDirDirent): boolean {
  if (direntIsDirectory(dirent)) {
    return false
  }

  return direntIsSymbolicLink(dirent) || !direntIsFile(dirent)
}

async function entryForDirent(dirent: ReadDirDirent, resolved: string, fsImpl: ReadDirFs): Promise<ReadDirEntry> {
  const fullPath = path.join(resolved, dirent.name)
  let isDirectory = direntIsDirectory(dirent)

  if (!isDirectory && shouldStatDirent(dirent)) {
    try {
      // A stub without `stat` throws here and falls through to the catch, the
      // same as any other stat failure.
      isDirectory = (await fsImpl.promises.stat!(fullPath)).isDirectory()
    } catch {
      isDirectory = false
    }
  }

  return { name: dirent.name, path: fullPath, isDirectory }
}

async function mapWithStatConcurrency<Item, Result>(
  items: Item[],
  mapper: (item: Item) => Promise<Result>
): Promise<Result[]> {
  const results = new Array<Result>(items.length)
  let nextIndex = 0

  async function runWorker(): Promise<void> {
    while (nextIndex < items.length) {
      const index = nextIndex
      nextIndex += 1
      // `index < items.length` was just checked, so the element exists.
      results[index] = await mapper(items[index]!)
    }
  }

  const workerCount = Math.min(FS_READDIR_STAT_CONCURRENCY, items.length)
  const workers = Array.from({ length: workerCount } as any, () => runWorker())
  await Promise.all(workers)

  return results
}

async function readDirForIpc(
  dirPath: unknown,
  options: { fs?: ReadDirFs | undefined } = {}
): Promise<{ entries: ReadDirEntry[]; error?: string }> {
  const fsImpl: ReadDirFs = options.fs || fs
  let resolved: string

  // On a Windows host with a WSL backend, a WSL/POSIX cwd (`/home/...`,
  // `/mnt/c/...`) isn't readable as-is; bridge it to a UNC/drive form first.
  const readPath = resolveLocalReadPath(String(dirPath ?? ''))

  try {
    ;({ resolvedPath: resolved } = await resolveDirectoryForIpc(readPath, {
      fs: fsImpl,
      purpose: 'Directory read'
    }))
  } catch (error) {
    return { entries: [], error: errorCode(error) || 'read-error' }
  }

  try {
    const dirents = await fsImpl.promises.readdir(resolved, { withFileTypes: true })
    const visibleDirents = dirents.filter(dirent => !FS_READDIR_HIDDEN.has(dirent.name))
    const entries = await mapWithStatConcurrency(visibleDirents, dirent => entryForDirent(dirent, resolved, fsImpl))

    entries.sort((a, b) => Number(b.isDirectory) - Number(a.isDirectory) || a.name.localeCompare(b.name))

    return { entries }
  } catch (error) {
    return { entries: [], error: errorCode(error) || 'read-error' }
  }
}

export { readDirForIpc }
