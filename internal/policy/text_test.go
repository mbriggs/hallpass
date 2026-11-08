package policy

import "testing"

// A command a bot acts on is refused whatever invisible or non-ASCII
// characters come before it, and whatever starts its line.
func TestCheckTextUnicode(t *testing.T) {
	refused := map[string]string{
		"nbsp":                "\u00a0/merge",
		"bom":                 "\ufeff/merge",
		"ideographic space":   "\u3000/merge",
		"zero-width space":    "\u200b/merge",
		"vertical tab":        "\v/merge",
		"vertical tab break":  "looks good\v/merge",
		"form feed break":     "looks good\f/merge",
		"file separator":      "looks good\x1c/merge",
		"group separator":     "looks good\x1d/merge",
		"record separator":    "looks good\x1e/merge",
		"line separator":      "looks good\u2028/merge",
		"bors after nbsp":     "\u00a0bors r+",
		"plain":               "/merge",
		"after a normal line": "looks good\n  /merge",
	}
	for name, s := range refused {
		if err := CheckText(s); err == nil {
			t.Errorf("%s: %q allowed", name, s)
		}
	}
	allowed := []string{"see a/merge here", "\u00a0looks good", "merge when ready", "borscht recipe"}
	for _, s := range allowed {
		if err := CheckText(s); err != nil {
			t.Errorf("%q refused: %v", s, err)
		}
	}
}

// A line that starts with an absolute path isn't a slash command, but a
// slash command followed by punctuation or arguments still is.
func TestCheckTextPaths(t *testing.T) {
	refused := []string{
		"/merge", "/merge.", "/merge, please", "/lgtm cancel", "/hold\tcancel",
		"/test all", "/label kind/bug", "/assign @someone", "/merge-it",
		"/merge.yml", "/merge:now", "/usr",
	}
	for _, s := range refused {
		if err := CheckText(s); err == nil {
			t.Errorf("%q allowed", s)
		}
	}
	allowed := []string{
		"/tmp/bunk-verify-evidence, and a teardown that removes only what the run",
		"/Users/mbriggs/src/hallpass is the primary",
		"/opt/hallpass/bin/hallpass gh pr view",
		"/tmp/",
		"  /var/log/system.log",
		"/",
		"/1234",
	}
	for _, s := range allowed {
		if err := CheckText(s); err != nil {
			t.Errorf("%q refused: %v", s, err)
		}
	}
}
