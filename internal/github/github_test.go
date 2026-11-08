package github

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseRepo(t *testing.T) {
	for in, want := range map[string]string{"acme/widgets": "acme/widgets", "/acme/widgets.git/": "acme/widgets"} {
		if r, err := ParseRepo(in); err != nil || r.String() != want {
			t.Errorf("ParseRepo(%q) = %v, %v", in, r, err)
		}
	}
	for _, in := range []string{"acme", "acme/../x", "../x", "a/b/c", "a/b c"} {
		if _, err := ParseRepo(in); err == nil {
			t.Errorf("ParseRepo(%q) accepted", in)
		}
	}
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
