package codeowners

import (
	"strings"

	"github.com/hmarr/codeowners"
)

// Owner represents a parsed CODEOWNERS entry — either a user (@username)
// or a team (@org/team-slug).
type Owner struct {
	Raw      string // original string e.g. "@acme/platform"
	IsTeam   bool
	OrgSlug  string  // "acme" for @acme/platform
	TeamSlug string  // "platform" for @acme/platform
	Username string  // for plain @username
}

// Match pairs a file pattern with its resolved owners.
type Match struct {
	Pattern string
	Owners  []Owner
}

// ParseOwners parses CODEOWNERS file content and returns a Ruleset
// that can match file paths to their owners.
type Ruleset struct {
	rules codeowners.Ruleset
}

// Parse builds a Ruleset from the raw CODEOWNERS file content.
// Returns an empty ruleset (no matches) if content is empty.
func Parse(content string) (*Ruleset, error) {
	if strings.TrimSpace(content) == "" {
		return &Ruleset{}, nil
	}

	rs, err := codeowners.ParseFile(strings.NewReader(content))
	if err != nil {
		return nil, err
	}
	return &Ruleset{rules: rs}, nil
}

// OwnersForPath returns all owners responsible for the given path.
// path should be relative to the repository root (e.g. "services/auth/go.mod").
func (r *Ruleset) OwnersForPath(path string) []Owner {
	if r.rules == nil {
		return nil
	}

	rule, err := r.rules.Match(path)
	if err != nil || rule == nil {
		return nil
	}

	owners := make([]Owner, 0, len(rule.Owners))
	for _, o := range rule.Owners {
		owners = append(owners, parseOwner(o.Value))
	}
	return owners
}

// MatchesForPaths returns a Match per path, only for paths that have at least one owner.
func (r *Ruleset) MatchesForPaths(paths []string) []Match {
	var matches []Match
	seen := map[string]bool{}

	for _, path := range paths {
		owners := r.OwnersForPath(path)
		if len(owners) == 0 {
			continue
		}

		rule, _ := r.rules.Match(path)
		pattern := ""
		if rule != nil {
			pattern = rule.RawPattern()
		}

		key := pattern
		if seen[key] {
			continue
		}
		seen[key] = true

		matches = append(matches, Match{Pattern: pattern, Owners: owners})
	}
	return matches
}

// TeamsFromOwners filters and returns only team owners (@org/team-slug).
func TeamsFromOwners(owners []Owner) []Owner {
	var teams []Owner
	for _, o := range owners {
		if o.IsTeam {
			teams = append(teams, o)
		}
	}
	return teams
}

func parseOwner(raw string) Owner {
	o := Owner{Raw: raw}
	// Remove leading @
	name := strings.TrimPrefix(raw, "@")

	parts := strings.SplitN(name, "/", 2)
	if len(parts) == 2 {
		o.IsTeam = true
		o.OrgSlug = parts[0]
		o.TeamSlug = parts[1]
	} else {
		o.IsTeam = false
		o.Username = name
	}
	return o
}
