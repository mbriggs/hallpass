// Package github names repos and checks, gets, and revokes the broker's
// GitHub token.
package github

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Repo is an owner/name pair checked against GitHub's allowed characters, so
// it is safe to put in a path.
type Repo struct {
	Owner, Name string
}

var repoPart = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)

// ParseRepo accepts "owner/name", with an optional ".git" suffix or
// surrounding slashes.
func ParseRepo(s string) (Repo, error) {
	s = strings.TrimSuffix(strings.Trim(s, "/"), ".git")
	owner, name, ok := strings.Cut(s, "/")
	if !ok || !repoPart.MatchString(owner) || !repoPart.MatchString(name) ||
		owner == "." || owner == ".." || name == "." || name == ".." {
		return Repo{}, fmt.Errorf("not a GitHub repo path: %q", s)
	}
	return Repo{owner, name}, nil
}

func (r Repo) String() string { return r.Owner + "/" + r.Name }

// Key is the repo in a form for map keys and comparisons: GitHub treats
// owner and name case-insensitively.
func (r Repo) Key() string { return strings.ToLower(r.String()) }

// TokenInfo is what GitHub says about a token.
type TokenInfo struct {
	Login  string
	Scopes []string
	// Expires is zero when the token doesn't expire.
	Expires time.Time
}

// ErrBadToken means GitHub rejected the token.
var ErrBadToken = errors.New("GitHub rejected the token")

// CheckToken asks GitHub who the token belongs to and what it may do.
func CheckToken(ctx context.Context, client *http.Client, api, token string) (TokenInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", api+"/user", nil)
	if err != nil {
		return TokenInfo{}, err
	}
	req.Header.Set("Authorization", "token "+token)
	resp, err := do(client, req)
	if err != nil {
		return TokenInfo{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusUnauthorized {
		return TokenInfo{}, ErrBadToken
	}
	if resp.StatusCode != http.StatusOK {
		return TokenInfo{}, httpErr(resp, body)
	}
	var user struct{ Login string }
	if err := json.Unmarshal(body, &user); err != nil {
		return TokenInfo{}, err
	}
	info := TokenInfo{Login: user.Login}
	for _, s := range strings.Split(resp.Header.Get("X-OAuth-Scopes"), ",") {
		if s = strings.TrimSpace(s); s != "" {
			info.Scopes = append(info.Scopes, s)
		}
	}
	slices.Sort(info.Scopes)
	if exp := resp.Header.Get("GitHub-Authentication-Token-Expiration"); exp != "" {
		// GitHub sends "2027-02-06 00:00:00 UTC".
		t, err := time.Parse("2006-01-02 15:04:05 MST", exp)
		if err != nil {
			t, err = time.Parse("2006-01-02 15:04:05 -0700", exp)
		}
		if err == nil {
			info.Expires = t
		}
	}
	return info, nil
}

// Revoke asks GitHub to revoke a token by its value. The endpoint needs no
// authentication, and GitHub emails the token's owner.
func Revoke(ctx context.Context, client *http.Client, api, token string) error {
	b, _ := json.Marshal(map[string][]string{"credentials": {token}})
	req, err := http.NewRequestWithContext(ctx, "POST", api+"/credentials/revoke", bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := do(client, req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return httpErr(resp, body)
	}
	return nil
}

// GitHub CLI's OAuth client ID, which it publishes in its source. Device
// login borrows it so orgs that approved GitHub CLI accept the token.
const ghClientID = "178c6fc778ccc68e1d6a"

// DeviceCode is the first step of a device login.
type DeviceCode struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

// StartDeviceLogin asks GitHub for a code the user enters in a browser.
func StartDeviceLogin(ctx context.Context, client *http.Client, web, scope string) (DeviceCode, error) {
	var dc DeviceCode
	err := form(ctx, client, web+"/login/device/code", url.Values{"client_id": {ghClientID}, "scope": {scope}}, &dc)
	return dc, err
}

// FinishDeviceLogin polls until the user approves the code, then returns the
// token.
func FinishDeviceLogin(ctx context.Context, client *http.Client, web string, dc DeviceCode) (string, error) {
	interval := time.Duration(max(dc.Interval, 5)) * time.Second
	deadline := time.Now().Add(time.Duration(dc.ExpiresIn) * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(interval):
		}
		var r struct {
			AccessToken string `json:"access_token"`
			Error       string `json:"error"`
			Desc        string `json:"error_description"`
		}
		err := form(ctx, client, web+"/login/oauth/access_token", url.Values{
			"client_id":   {ghClientID},
			"device_code": {dc.DeviceCode},
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		}, &r)
		if err != nil {
			return "", err
		}
		switch r.Error {
		case "":
			if r.AccessToken == "" {
				return "", errors.New("GitHub returned no token")
			}
			return r.AccessToken, nil
		case "authorization_pending":
		case "slow_down":
			interval += 5 * time.Second
		default:
			return "", fmt.Errorf("device login: %s: %s", r.Error, r.Desc)
		}
	}
	return "", errors.New("the device code expired before it was approved")
}

func form(ctx context.Context, client *http.Client, u string, v url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, "POST", u, strings.NewReader(v.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := do(client, req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return httpErr(resp, body)
	}
	return json.Unmarshal(body, out)
}

func do(client *http.Client, req *http.Request) (*http.Response, error) {
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "hallpass")
	return client.Do(req)
}

func httpErr(resp *http.Response, body []byte) error {
	var msg struct{ Message string }
	_ = json.Unmarshal(body, &msg)
	if msg.Message == "" {
		msg.Message = strings.TrimSpace(string(body))
	}
	return fmt.Errorf("GitHub returned %d: %s", resp.StatusCode, msg.Message)
}
