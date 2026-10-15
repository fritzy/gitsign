// Copyright 2026 The Sigstore Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fulcio

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type hintTransport func(*http.Request) (*http.Response, error)

func (f hintTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestGoogleLoginURL(t *testing.T) {
	original := "https://oauth2.sigstore.dev/auth/auth?connector_id=https%3A%2F%2Faccounts.google.com&redirect_uri=http%3A%2F%2Flocalhost%3A34567%2Fcallback&state=original"
	google := "https://accounts.google.com/o/oauth2/auth?state=dex-state&redirect_uri=https%3A%2F%2Foauth2.sigstore.dev%2Fauth%2Fcallback&client_id=google-client&scope=openid+email"
	calls := 0
	transport := hintTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		location := "/auth/google?req=request-id"
		if calls == 2 {
			location = google
		}
		if r.URL.Host != "oauth2.sigstore.dev" {
			t.Fatalf("contacted unexpected host %s", r.URL.Host)
		}
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": {location}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	})
	got, err := googleLoginURL(context.Background(), transport, original, "work+git@example.com")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("login_hint") != "work+git@example.com" || calls != 2 {
		t.Fatalf("unexpected hint or request count: %s, %d", got, calls)
	}
	q.Del("login_hint")
	expected, _ := url.Parse(google)
	if q.Encode() != expected.Query().Encode() {
		t.Fatalf("OAuth parameters changed: %s", got)
	}
}

func TestGoogleLoginURLFailures(t *testing.T) {
	original := "https://oauth2.sigstore.dev/auth/auth?connector_id=https%3A%2F%2Faccounts.google.com"
	for _, location := range []string{"https://evil.example/", "http://accounts.google.com/auth", "https://accounts.google.com.evil.example/", "https://user@accounts.google.com/auth", "https://oauth2.sigstore.dev/loop"} {
		t.Run(location, func(t *testing.T) {
			calls := 0
			transport := hintTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: 302, Header: http.Header{"Location": {location}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
			})
			if _, err := googleLoginURL(context.Background(), transport, original, "work@example.com"); err == nil {
				t.Fatal("expected redirect rejection")
			}
			if calls > 5 {
				t.Fatalf("too many requests: %d", calls)
			}
		})
	}
}

func TestGoogleLoginURLUnchanged(t *testing.T) {
	transport := hintTransport(func(*http.Request) (*http.Response, error) { t.Fatal("unexpected network request"); return nil, nil })
	for _, original := range []string{"https://custom.example/auth?login_hint=work%40example.com", "https://oauth2.sigstore.dev/auth/auth?connector_id=github", "http://oauth2.sigstore.dev/auth/auth?connector_id=https%3A%2F%2Faccounts.google.com"} {
		got, err := googleLoginURL(context.Background(), transport, original, "work@example.com")
		if err != nil || got != original {
			t.Fatalf("got %q, %v", got, err)
		}
	}
}

func TestLoginHintBridge(t *testing.T) {
	original := "https://oauth2.sigstore.dev/auth/auth?redirect_uri=http%3A%2F%2Flocalhost%3A34567%2Fcallback"
	target := "https://accounts.google.com/auth?login_hint=work%40example.com&state=unchanged"
	bridge, closeBridge, err := loginHintBridge(original, target)
	if err != nil {
		t.Fatal(err)
	}
	defer closeBridge()
	u, _ := url.Parse(bridge)
	if u.Hostname() != "127.0.0.1" || u.Query().Get("redirect_uri") != "http://localhost:34567/callback" {
		t.Fatalf("relay callback lost: %s", bridge)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(bridge)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 302 || resp.Header.Get("Location") != target || resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("unexpected bridge response: %#v", resp)
	}
	u.Path = "/wrong-path"
	resp, err = client.Get(u.String())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("unprotected redirect: %d", resp.StatusCode)
	}
	closeBridge()
	if resp, err = client.Get(bridge); err == nil {
		resp.Body.Close()
		t.Fatal("bridge still listening")
	}
}
