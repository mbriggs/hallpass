package github

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseRepo(t *testing.T) {
	for in, want := range map[string]string{"acme/widgets": "acme/widgets", "/acme/widgets.git/": "acme/widgets"} {
		if r, err := ParseRepo(in); err != nil || r.String() != want {
			t.Errorf("ParseRepo(%q) = %v, %v", in, r, err)
		}
	}
	for _, in := range []string{"acme", "acme/../x", "../x", "a/b/c", "a/b c", "a/b.git.git"} {
		if _, err := ParseRepo(in); err == nil {
			t.Errorf("ParseRepo(%q) accepted", in)
		}
	}
}

// The SSH gate runs `<service> '<owner>/<name>.git'` on GitHub, and the
// broker matches repos against its allowlist by name. So a repo ParseRepo
// accepts can't hold a quote or a path step, and its name means the same
// repo when parsed again.
func FuzzParseRepo(f *testing.F) {
	for _, s := range []string{"acme/widgets", "/acme/widgets.git", "a.b/c-d_e", "acme/..", "acme/widgets/extra", "acme/widgets.git.git"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r, err := ParseRepo(s)
		if err != nil {
			return
		}
		for _, part := range []string{r.Owner, r.Name} {
			if part == "" || part == "." || part == ".." ||
				strings.Trim(part, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-") != "" {
				t.Fatalf("ParseRepo(%q) = %q", s, r)
			}
		}
		if again, err := ParseRepo(r.String()); err != nil || again != r {
			t.Fatalf("ParseRepo(%q) = %q, but %q parses as %q, %v", s, r, r.String(), again, err)
		}
	})
}

func TestCheckToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "token good" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("X-OAuth-Scopes", "repo, read:org")
		w.Header().Set("GitHub-Authentication-Token-Expiration", "2027-02-06 00:00:00 UTC")
		w.Write([]byte(`{"login":"mbriggs"}`))
	}))
	defer srv.Close()
	info, err := CheckToken(context.Background(), nil, srv.URL, "good")
	if err != nil || info.Login != "mbriggs" || len(info.Scopes) != 2 || info.Scopes[0] != "read:org" || info.Expires.Year() != 2027 {
		t.Fatalf("CheckToken = %+v, %v", info, err)
	}
	if _, err := CheckToken(context.Background(), nil, srv.URL, "bad"); !errors.Is(err, ErrBadToken) {
		t.Fatalf("bad token: %v", err)
	}
}
