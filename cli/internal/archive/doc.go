// Package archive extracts a verified tar+zstd bundle under hard caps, refusing every member kind and
// path shape that could write outside its destination.
//
// Path, member-kind and size decisions are archiveguard's; this package owns the on-disk half (os.Root,
// O_EXCL, plugin adoption, case-fold collisions). File content is fsynced here because the swap's
// parent fsync only makes the directory entry durable.
package archive
