package checks

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"

	"agent-manager/internal/bundle"
	"agent-manager/internal/worker/scanner/rules"
)

// Verify applies every rule in a pack to the two fixtures it ships: the one that
// must trip it and the one that must not.
//
// The constitution requires both, and this is the reason the second one is not
// optional. A rule with only a positive fixture is how a rule that matches
// everything ships — it demonstrably fires, the pack loads, the tests are green,
// and every package in the catalog is flagged for a reason no reviewer can act
// on. The negative fixture is the only artefact that distinguishes "this rule
// detects something" from "this rule detects anything".
//
// It lives in the production build rather than only in a test so a pack mounted
// at AGENT_MANAGER_RULEPACK_DIR can be checked by the same code that will run it.
func Verify(ctx context.Context, pack *rules.Pack) error {
	if pack == nil {
		return errors.New("verify: no rule pack")
	}

	var problems []string
	all := pack.All()
	// Indexed: a Rule carries its compiled pattern and scope.
	for i := range all {
		rule := all[i]
		tripped, err := fixtureFindings(ctx, pack, rule, rule.Fixtures.Trips)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", rule.ID, err))
		} else if len(tripped) == 0 {
			problems = append(problems, fmt.Sprintf(
				"%s: its `trips` fixture %s raised no finding, so the rule detects nothing",
				rule.ID, rule.Fixtures.Trips))
		}

		clean, err := fixtureFindings(ctx, pack, rule, rule.Fixtures.Clean)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", rule.ID, err))
		} else if len(clean) > 0 {
			problems = append(problems, fmt.Sprintf(
				"%s: its `clean` fixture %s raised %d finding(s) at %s, so the rule matches more than it describes",
				rule.ID, rule.Fixtures.Clean, len(clean), clean[0].Primary().Path))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("rule pack %s fails its own fixtures:\n  %s",
			pack.Version(), strings.Join(problems, "\n  "))
	}
	return nil
}

func fixtureFindings(ctx context.Context, pack *rules.Pack, rule rules.Rule, fixture string) ([]Finding, error) {
	if fixture == "" {
		return nil, errors.New("declares no fixture path")
	}
	fsys, err := pack.FixtureFS(fixture)
	if err != nil {
		return nil, err
	}
	tree, err := Tree(fsys)
	if err != nil {
		return nil, fmt.Errorf("read fixture %s: %w", fixture, err)
	}
	inspected, err := Inspect(tree)
	if err != nil {
		return nil, fmt.Errorf("inspect fixture %s: %w", fixture, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return apply(inspected, rule)
}

// Tree reads a package tree out of any filesystem into the same in-memory bundle
// a stored version unpacks to, so a fixture on disk and a bundle out of the object
// store are the same input to the checks.
func Tree(fsys fs.FS) (*bundle.Bundle, error) {
	tree := bundle.New()
	err := fs.WalkDir(fsys, ".", func(entry string, dir fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case dir.IsDir():
			return nil
		case !dir.Type().IsRegular():
			// A fixture is a package tree, and the extractor refuses symlinks and
			// device nodes in an archive member (internal/bundle). Accepting one here
			// would make a fixture able to reach outside itself.
			return fmt.Errorf("%s is not a regular file", entry)
		}

		data, readErr := fs.ReadFile(fsys, entry)
		if readErr != nil {
			return readErr
		}
		mode := bundle.FileMode
		if strings.HasSuffix(path.Base(entry), ".sh") {
			mode = bundle.ExecMode
		}
		return tree.Add(path.Clean(entry), mode, data)
	})
	if err != nil {
		return nil, err
	}
	return tree, nil
}
