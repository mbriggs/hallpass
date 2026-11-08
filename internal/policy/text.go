package policy

import (
	"regexp"
	"strings"
)

// chatOps matches lines that bots in many orgs act on. hallpass posts as
// the user, so a bot would take one of these as the user's command, for
// example to merge. The list can't cover every bot.
var chatOps = []*regexp.Regexp{
	regexp.MustCompile(`^\s*/[A-Za-z]`),
	regexp.MustCompile(`(?i)^\s*bors\b`),
	regexp.MustCompile(`(?i)@(mergifyio|mergify|dependabot|renovate|bors|kodiakhq|k8s-ci-robot)\b`),
}

// CheckStrings runs CheckText over every string in a decoded JSON value.
func CheckStrings(v any) error {
	switch t := v.(type) {
	case string:
		return CheckText(t)
	case map[string]any:
		for _, e := range t {
			if err := CheckStrings(e); err != nil {
				return err
			}
		}
	case []any:
		for _, e := range t {
			if err := CheckStrings(e); err != nil {
				return err
			}
		}
	}
	return nil
}

// lineBreaks are what bots may split lines on, beyond \n.
var lineBreaks = strings.NewReplacer("\r", "\n", "\u2028", "\n", "\u2029", "\n", "\u0085", "\n")

// CheckText refuses PR, issue, and comment text with lines bots act on.
func CheckText(s string) error {
	for _, line := range strings.Split(lineBreaks.Replace(s), "\n") {
		for _, re := range chatOps {
			if re.MatchString(line) {
				return errorf("hallpass doesn't post text with the line %q, because bots act on lines like it as your command. Rephrase it", strings.TrimSpace(line))
			}
		}
	}
	return nil
}
