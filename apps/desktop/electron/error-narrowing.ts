// Shared narrowing for `catch (error: unknown)` in the Electron main process.
// Strict TypeScript types catch bindings as `unknown`, and the privileged
// modules all reach for the same two things off a thrown value: the errno-style
// `code` and a printable message. Keeping that in one place beats repeating the
// `error && typeof error === 'object'` dance at every catch site.

/**
 * The errno-style `code` of a thrown value, or `undefined` when it carries
 * none. Node's `fs` / `child_process` rejections are `ErrnoException`s whose
 * `code` is a string, so the assertion is a type-level statement about the
 * values these modules actually catch — nothing is coerced at runtime, which
 * keeps the result identical to reading `error.code` directly.
 */
export function errorCode(error: unknown): string | undefined {
  return error !== null && typeof error === 'object' ? (error as NodeJS.ErrnoException).code : undefined
}

/** A printable message for a thrown value: `error.message`, else `String(error)`. */
export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}
