package policy

import (
	"regexp"
	"strings"
	"unicode"
)

// chatOps matches lines that bots in many orgs act on. hallpass posts as
// the user, so a bot would take one of these as the user's command, for
// example to merge. The list can't cover every bot.
// CheckText trims each line before matching, because \s in Go's regexps
// is ASCII only.
var chatOps = []*regexp.Regexp{
	regexp.MustCompile(`^/[A-Za-z]`),
	regexp.MustCompile(`(?i)^bors\b`),
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

// lineBreaks are what bots may split lines on, beyond \n: every character
// Unicode or a line-oriented parser treats as ending a line.
var lineBreaks = strings.NewReplacer(
	"\r", "\n", "\v", "\n", "\f", "\n",
	"\x1c", "\n", "\x1d", "\n", "\x1e", "\n",
	"\u0085", "\n", "\u2028", "\n", "\u2029", "\n",
)

// leading is what a bot may skip before a command: any Unicode space, and
// invisible format characters like a byte-order mark or zero-width space.
func leading(r rune) bool {
	return unicode.IsSpace(r) || unicode.Is(unicode.Cf, r)
}

// CheckText refuses PR, issue, and comment text with lines bots act on.
func CheckText(s string) error {
	for line := range strings.SplitSeq(lineBreaks.Replace(s), "\n") {
		trimmed := strings.TrimLeftFunc(line, leading)
		for _, re := range chatOps {
			if re.MatchString(trimmed) {
				return errorf("hallpass doesn't post text with the line %q, because bots act on lines like it as your command. Rephrase it", strings.TrimSpace(line))
			}
		}
	}
	return nil
}
