package main

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
)

// The account and token gh sees, from system.GHHostsText. The broker holds
// the real token, so these are what gh auth reports.
const (
	ghAuthUser  = "hallpass"
	ghAuthToken = "hallpass-brokered"
)

// ghAuth answers gh auth subcommands itself, so tools that wrap gh see a
// logged-in gh. The real gh can't: its config is read-only, and gh auth
// status asks GitHub for GET /, which the broker refuses. handled is false
// for help and subcommands this doesn't know, which go to the real gh.
func ghAuth(args []string, stdin io.Reader, stdout, stderr io.Writer) (handled bool, err error) {
	if len(args) < 2 || args[0] != "auth" {
		return false, nil
	}
	sub, flags := args[1], args[2:]
	// Under gh auth, -h is --hostname, so only --help asks for help.
	if slices.Contains(flags, "--help") {
		return false, nil
	}
	switch sub {
	case "status":
		return true, ghAuthStatus(flags, stdout)
	case "token":
		fmt.Fprintln(stdout, ghAuthToken)
		return true, nil
	case "git-credential":
		// No answer, so git asks the next helper: hallpass credential,
		// which stops git.
		_, _ = io.Copy(io.Discard, stdin)
		return true, nil
	case "login":
		if slices.Contains(flags, "--with-token") {
			_, _ = io.Copy(io.Discard, stdin)
		}
		fmt.Fprintf(stderr, "hallpass: already logged in to github.com as %s; the hallpass broker holds the token.\n", ghAuthUser)
		return true, nil
	case "logout", "refresh", "switch", "setup-git":
		fmt.Fprintf(stderr, "hallpass: gh auth %s does nothing here; the hallpass broker holds the token.\n", sub)
		return true, nil
	}
	return false, nil
}

func ghAuthStatus(flags []string, stdout io.Writer) error {
	showToken := false
	asJSON := false
	for i := 0; i < len(flags); i++ {
		f := flags[i]
		name, _, hasValue := strings.Cut(f, "=")
		switch name {
		case "-t", "--show-token":
			showToken = true
		case "-a", "--active":
		case "--json":
			asJSON = true
			if !hasValue {
				i++
			}
		case "-h", "--hostname":
			if !hasValue {
				i++
			}
		case "--jq", "--template", "-q":
			return fmt.Errorf("gh auth status %s isn't supported through hallpass; use --json hosts", name)
		}
	}
	if asJSON {
		type account struct {
			State       string `json:"state"`
			Active      bool   `json:"active"`
			Host        string `json:"host"`
			Login       string `json:"login"`
			TokenSource string `json:"tokenSource"`
			Token       string `json:"token,omitempty"`
			GitProtocol string `json:"gitProtocol"`
		}
		a := account{State: "success", Active: true, Host: "github.com", Login: ghAuthUser, TokenSource: "hallpass", GitProtocol: "https"}
		if showToken {
			a.Token = ghAuthToken
		}
		return json.NewEncoder(stdout).Encode(map[string]any{"hosts": map[string][]account{"github.com": {a}}})
	}
	token := "hallpass-********"
	if showToken {
		token = ghAuthToken
	}
	fmt.Fprintf(stdout, `github.com
  ✓ Logged in to github.com account %s (hallpass)
  - Active account: true
  - Git operations protocol: https
  - Token: %s
  - Requests go through the hallpass broker, which holds the real token.
`, ghAuthUser, token)
	return nil
}
