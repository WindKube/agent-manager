// Package fake serves the seven hub operations the CLI uses, in process, over a real TCP listener,
// with real zstd bundle bytes and real digests.
//
// A behavioural test must take a [Target], never a *fake.Hub, so it can also run against the real hub;
// a case the fake can't express says so ([Fixtures] empty, [ErrUnsupported]) and the suite skips visibly.
package fake
