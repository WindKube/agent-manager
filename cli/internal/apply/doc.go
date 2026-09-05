// Package apply is the only package permitted to mutate the filesystem: it
// stages a verified bundle, swaps it in atomically, then prunes by lockfile.
package apply
