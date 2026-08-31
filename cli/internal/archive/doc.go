// Package archive extracts a verified bundle (tar, zstd-compressed) onto the local
// filesystem under hard caps, refusing every member kind and path shape that could
// write outside the tree it was given.
//
// # This package deliberately duplicates the hub's agent-manager/internal/bundle
//
// It is NOT a missed abstraction and it must not be "deduplicated". The CLI is the
// last hop before a developer's disk, so it must not trust the hub's extraction:
// the hub could be wrong, compromised, or a redirect could be poisoned. Sharing the
// code would mean a shared module and, more importantly, a shared bug — the one
// failure mode defence in depth exists to survive. The caps here are the SAME
// NUMBERS as agent-manager/internal/bundle/limits.go, copied on purpose; the code
// that enforces them is independent on purpose. See "Complexity Tracking" in
// specs/002-agent-manager-cli/plan.md, which records this as an accepted deviation.
//
// If you are here to import agent-manager/internal/bundle, add a replace directive,
// or lift a shared module out of the two: don't. No test would fail, and the
// defence in depth would be gone.
//
// # What this package refuses
//
// Caps, every one of them enforced WHILE STREAMING and never after (FR-019) —
// a ratio cap checked after extraction is not a cap, the bomb has already landed:
// compressed size, total decompressed size, compression ratio, entry count,
// per-entry size, path depth, path length, wall clock.
//
// Members refused outright: absolute paths (including a drive-letter spelling),
// `..` surviving path.Clean, backslashes and NULs in a path, symlinks, hardlinks,
// device nodes, FIFOs, any other exotic tar type, duplicate paths, and — R2 — a
// skill root containing any of the subdirectory names that make Claude Code adopt
// the directory as a PLUGIN rather than a skill (see
// layout.IsClaudeCodePluginAdoptingSubdir). A bundle carrying one of those changes
// its own kind on disk, acquiring lifecycle hooks, monitors and MCP servers.
//
// Destinations refused: any path component under the destination root that this
// extraction did not itself create. That single invariant is what keeps a write
// inside the root — os.Mkdir cannot create a symlink, so every directory on every
// written path is known to be a real directory we made, and the leaf is opened
// O_EXCL. os.Root is the backstop underneath it: every filesystem call goes
// through it, so even a component swapped concurrently cannot resolve outside the
// root.
//
// # Formats this package does NOT accept
//
// Only tar+zstd, checked by magic before a decoder is constructed. The hub serves
// exactly one format ("Content-Type: application/zstd", produced by the hub's
// bundle.Pack), so accepting .zip or .tar.gz as well would be attack surface with
// no caller. zip in particular needs random access and has the two-central-
// directories ambiguity; there is no reason to carry that here.
//
// # Durability: this package owns file CONTENT, the swap owns directory ENTRIES
//
// Every extracted file is fsynced before Extract returns, and every directory it
// created — including the destination root — is fsynced best-effort. This is not
// belt-and-braces: R3 established that fsyncing the parent of the destination
// during the atomic swap (T041 step 4) makes the directory ENTRY durable, not the
// CONTENT beneath it. On a delayed-allocation filesystem a power loss just after
// the swap would otherwise leave the destination present and full of zero-length
// files — a mixture, and an FR-024 violation that no care in swap.go can prevent.
// Content durability is the extractor's; directory-entry durability is the swap's.
// Do not move the file fsync into apply/stage.go, and do not delete it as
// redundant with the swap's fsync: they cover different objects.
//
// A file fsync failure is fatal. A directory fsync failure is not: the write
// ordering — the installation record is written after the swap — is what keeps
// state consistent, and the fsync only narrows a window.
package archive
