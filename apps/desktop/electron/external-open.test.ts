import assert from 'node:assert/strict'

import { test } from 'vitest'

import { EXTERNALLY_OPENABLE_EXTS, isExternallyOpenablePath } from './external-open'

// ---------------------------------------------------------------------------
// The point of the gate: `shell.openPath` executes what the OS associates with
// the extension, and the caller is reachable from model output.

test('executable file types are refused', () => {
  for (const filePath of [
    '/Users/me/Downloads/install.command',
    '/home/me/.local/share/applications/hermes.desktop',
    'C:\\Users\\me\\setup.bat',
    'C:\\Users\\me\\setup.cmd',
    'C:\\Users\\me\\setup.exe',
    'C:\\Users\\me\\setup.msi',
    '/tmp/deploy.sh',
    '/tmp/deploy.ps1',
    '/Applications/Calculator.app',
    '/tmp/payload.vbs',
    '/tmp/payload.jar',
    '/tmp/payload.scr'
  ]) {
    assert.equal(isExternallyOpenablePath(filePath), false, `${filePath} must not be handed to shell.openPath`)
  }
})

// The whole disguise: the eye stops at `.pdf`, the OS dispatches on `.command`.
test('a double extension is judged on the LAST extension, not the first', () => {
  assert.equal(isExternallyOpenablePath('/tmp/Q3 report.pdf.command'), false)
  assert.equal(isExternallyOpenablePath('/tmp/invoice.docx.exe'), false)
  assert.equal(isExternallyOpenablePath('/tmp/photo.png.sh'), false)

  // …and the benign direction still works.
  assert.equal(isExternallyOpenablePath('/tmp/archive.tar.gz.pdf'), true)
})

test('matching is case-insensitive so .COMMAND cannot slip past', () => {
  assert.equal(isExternallyOpenablePath('/tmp/x.COMMAND'), false)
  assert.equal(isExternallyOpenablePath('/tmp/x.Bat'), false)
  assert.equal(isExternallyOpenablePath('/tmp/x.ExE'), false)

  assert.equal(isExternallyOpenablePath('/tmp/Report.PDF'), true)
  assert.equal(isExternallyOpenablePath('/tmp/Photo.JPG'), true)
})

// ---------------------------------------------------------------------------
// Documents and media must keep opening — a gate that breaks the feature is a
// worse outcome than the gap it closes.

test('documents and media a user would plausibly open are allowed', () => {
  for (const filePath of [
    '/tmp/report.pdf',
    '/tmp/notes.txt',
    '/tmp/README.md',
    '/tmp/data.csv',
    '/tmp/data.json',
    '/tmp/sheet.xlsx',
    '/tmp/doc.docx',
    '/tmp/deck.pptx',
    '/tmp/page.html',
    '/tmp/chart.png',
    '/tmp/photo.jpeg',
    '/tmp/clip.mp4',
    '/tmp/track.mp3'
  ]) {
    assert.equal(isExternallyOpenablePath(filePath), true, `${filePath} should still open externally`)
  }
})

test('macro-enabled Office formats are not allowed even though their inert siblings are', () => {
  assert.equal(isExternallyOpenablePath('/tmp/book.xlsx'), true)
  assert.equal(isExternallyOpenablePath('/tmp/book.xlsm'), false)
  assert.equal(isExternallyOpenablePath('/tmp/doc.docm'), false)
  assert.equal(isExternallyOpenablePath('/tmp/deck.pptm'), false)
})

// ---------------------------------------------------------------------------
// Extensionless paths and directories.

test('a plainly named directory is allowed when the caller stat-ed one', () => {
  assert.equal(isExternallyOpenablePath('/Users/me/Projects/hermes', { isDirectory: true }), true)
  assert.equal(isExternallyOpenablePath('/Users/me/notes', { isDirectory: true }), true)
  assert.equal(isExternallyOpenablePath('/tmp/out', { isDirectory: true }), true)
})

// A macOS bundle is a DIRECTORY, and shell.openPath on one launches it — so
// being a directory must not by itself buy a pass past the gate.
test('a macOS bundle directory is refused even though it stats as a directory', () => {
  for (const bundle of [
    '/Applications/Calculator.app',
    '/tmp/Evil.app',
    '/tmp/thing.bundle',
    '/tmp/installer.pkg',
    '/tmp/auto.workflow',
    '/tmp/panel.prefPane'
  ]) {
    assert.equal(isExternallyOpenablePath(bundle, { isDirectory: true }), false, `${bundle} must not be launched`)
  }
})

test('an extensionless file is refused', () => {
  assert.equal(isExternallyOpenablePath('/usr/local/bin/hermes'), false)
  assert.equal(isExternallyOpenablePath('/tmp/Makefile'), false)
  // A dotfile has no extension as far as path.extname is concerned.
  assert.equal(isExternallyOpenablePath('/home/me/.bashrc'), false)
  // A trailing dot is not an extension either.
  assert.equal(isExternallyOpenablePath('/tmp/report.pdf.'), false)
})

test('empty and non-string-ish input is refused rather than throwing', () => {
  assert.equal(isExternallyOpenablePath(''), false)
  assert.equal(isExternallyOpenablePath('   '), false)
  assert.equal(isExternallyOpenablePath(undefined as unknown as string), false)
  assert.equal(isExternallyOpenablePath(null as unknown as string), false)
})

// ---------------------------------------------------------------------------
// Shape of the allowlist itself.

test('the allowlist is an allowlist: entries are lowercase, dot-prefixed, and hold no executables', () => {
  for (const ext of EXTERNALLY_OPENABLE_EXTS) {
    assert.equal(ext, ext.toLowerCase(), `${ext} must be stored lowercase for case-insensitive lookup`)
    assert.ok(ext.startsWith('.'), `${ext} must be dot-prefixed to match path.extname`)
  }

  for (const banned of [
    '.app',
    '.bat',
    '.cmd',
    '.com',
    '.command',
    '.desktop',
    '.exe',
    '.jar',
    '.js',
    '.lnk',
    '.msi',
    '.pif',
    '.ps1',
    '.py',
    '.rb',
    '.scr',
    '.sh',
    '.vbs',
    '.wsf'
  ]) {
    assert.equal(EXTERNALLY_OPENABLE_EXTS.has(banned), false, `${banned} must never enter the allowlist`)
  }
})
