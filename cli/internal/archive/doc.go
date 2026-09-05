// Package archive extracts a verified tar+zstd bundle under hard caps, refusing
// every member kind and path shape that could write outside its destination.
//
// It deliberately duplicates the hub's internal/bundle rather than sharing it: the
// CLI is the last hop before a developer's disk and must not inherit a hub bug.
// Every cap is enforced while streaming, never after. File content is fsynced
// here because the swap's parent fsync only makes the directory entry durable.
package archive
