// Package archive extracts a verified tar+zstd bundle under hard caps, refusing
// every member kind and path shape that could write outside its destination.
//
// Every path, member-kind and size decision is archiveguard's, shared with the
// hub's internal/bundle; this package owns the on-disk half: os.Root, O_EXCL,
// the plugin-adoption rule and case-fold collisions. Every cap is enforced while
// streaming, never after. File content is fsynced
// here because the swap's parent fsync only makes the directory entry durable.
package archive
