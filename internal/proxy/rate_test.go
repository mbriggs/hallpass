package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mbriggs/hallpass/internal/config"
)

// The broker refuses requests once GitHub reports fewer than rateReserve
// left in the hour, and only for the core limit, until it resets.
func TestHoldsRateReserve(t *testing.T) {
	t.Parallel()
	future, past := time.Now().Add(time.Hour), time.Unix(1, 0)
	// Each answer reports a rate limit, and want is the status of the
	// request after it.
	steps := []struct {
		resource  string
		remaining int
		reset     time.Time
		want      int
	}{
		{"search", 0, future, 200},
		{"core", rateReserve, future, 200},
		{"core", 0, past, 200},
		{"core", rateReserve - 1, future, 429},
	}
	var n atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := steps[min(int(n.Add(1))-1, len(steps)-1)]
		w.Header().Set("X-RateLimit-Resource", s.resource)
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(s.remaining))
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(s.reset.Unix(), 10))
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"full_name":"acme/widgets"}`)
	}))
	t.Cleanup(up.Close)
	client := ghClient(t, up.URL, config.Repo{Match: "acme/widgets"})
	get := func() int {
		resp, err := client.Get("http://api.github.com/repos/acme/widgets")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	get()
	for _, s := range steps {
		if got := get(); got != s.want {
			t.Errorf("after %d %s requests left: %d, want %d", s.remaining, s.resource, got, s.want)
		}
	}
}
