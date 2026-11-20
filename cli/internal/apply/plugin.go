package apply

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/WindKube/agent-manager/cli/internal/plan"
	"github.com/WindKube/agent-manager/cli/internal/record"
)

// removePlugin removes a plugin's components first and its unpacked copy
// last, so an interrupted removal still has a record row naming what is left.
func (a *Applier) removePlugin(ctx context.Context, r plan.Removal, res *Result) {
	fail := func(err error) {
		res.Failed = append(res.Failed, EntryError{Removal: &r, Err: err, Refusal: isRefusal(err)})
	}
	entry, ok := a.recordedEntry(r.Profile, r.Target, r.ID)
	if !ok {
		fail(fmt.Errorf("internal: no record row for %s (%s) in profile %s", r.ID, r.Target, r.Profile))
		return
	}

	kept, err := a.cfg.Components.Remove(ctx, r.Target, entry.Components)
	if err != nil {
		entry.Components = kept
		a.keepEntry(r.Profile, entry)
		fail(err)
		return
	}
	if err := a.removeTree(entry); err != nil {
		entry.Components = nil
		a.keepEntry(r.Profile, entry)
		fail(err)
		return
	}
	res.Removed = append(res.Removed, r)
}

func (a *Applier) recordedEntry(profile string, t record.Target, id string) (record.Entry, bool) {
	p, ok := a.cfg.Record.ProfileBySlug(profile)
	if !ok {
		return record.Entry{}, false
	}
	for i := range p.Entries {
		if p.Entries[i].ID == id && p.Entries[i].Target == t {
			return p.Entries[i], true
		}
	}
	return record.Entry{}, false
}

func (a *Applier) keepEntry(profile string, e record.Entry) {
	prof := a.profileRow(profile)
	prof.Entries = upsertEntry(prof.Entries, e)
	a.cfg.Record.SetProfile(prof)
}

// removeTree deletes an entry's own directory once it is proven unmodified.
func (a *Applier) removeTree(e record.Entry) error {
	cont, err := a.cfg.Home.Contains(e.Dest)
	if err != nil {
		return err
	}
	parent, name, err := splitDest(cont.Dest)
	if err != nil {
		return err
	}
	if _, lerr := os.Lstat(e.Dest); errors.Is(lerr, fs.ErrNotExist) {
		return a.removeAside(parent, name)
	}
	if verr := a.verifyRemovable(e); verr != nil {
		return verr
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return fmt.Errorf("open %s: %w", parent, err)
	}
	defer func() { _ = root.Close() }()
	if err := root.RemoveAll(name); err != nil {
		return fmt.Errorf("remove %s: %w", e.Dest, err)
	}
	return a.removeAside(parent, name)
}

func (a *Applier) verifyRemovable(e record.Entry) error {
	switch {
	case e.Fingerprint.IsZero():
		return a.override(fmt.Errorf("%w: %s was recorded without an install fingerprint", ErrUnverifiable, e.Dest),
			"%s: --force is removing %s, whose contents could not be verified", e.ID, e.Dest)
	case a.cfg.Verifier == nil:
		return a.override(fmt.Errorf("%w: %s carries a fingerprint and this build has no verifier for it",
			ErrUnverifiable, e.Dest), "%s: --force is removing %s without verifying it", e.ID, e.Dest)
	}
	changed, err := a.cfg.Verifier.Modifications(e)
	if err != nil {
		return a.override(fmt.Errorf("%w: %s: %w", ErrUnverifiable, e.Dest, err),
			"%s: --force is removing %s, which could not be verified (%v)", e.ID, e.Dest, err)
	}
	if len(changed) == 0 {
		return nil
	}
	return a.override(fmt.Errorf("%w: %s: %s", ErrModified, e.Dest, strings.Join(changed, ", ")),
		"%s: --force is removing %d modified path(s) under %s", e.ID, len(changed), e.Dest)
}

func (a *Applier) removeAside(parent, name string) error {
	root, err := os.OpenRoot(parent)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open %s: %w", parent, err)
	}
	defer func() { _ = root.Close() }()
	if err := root.RemoveAll(name + AsideSuffix); err != nil {
		return fmt.Errorf("remove %s%s: %w", name, AsideSuffix, err)
	}
	return nil
}
