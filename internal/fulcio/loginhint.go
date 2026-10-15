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
	"crypto/rand"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/pkg/browser"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"golang.org/x/oauth2"
)

type hintTokenGetter struct {
	flow *oauthflow.InteractiveIDTokenGetter
	hint string
	ctx  context.Context
}

func (g *hintTokenGetter) GetIDToken(provider *oidc.Provider, cfg oauth2.Config) (*oauthflow.OIDCIDToken, error) {
	flow := *g.flow
	open := flow.BrowserOpener
	if open == nil {
		open = browser.OpenURL
	}
	var closeBridge func()
	defer func() {
		if closeBridge != nil {
			closeBridge()
		}
	}()
	flow.BrowserOpener = func(original string) error {
		target, err := googleLoginURL(g.ctx, http.DefaultTransport, original, g.hint)
		if err != nil {
			// A hint is optional; preserve the normal browser login on failure.
			fmt.Fprintln(flow.GetOutput(), "Could not apply Google account hint; opening normal login.") // nolint:errcheck
			return open(original)
		}
		if target == original {
			return open(original)
		}
		bridge, cleanup, err := loginHintBridge(original, target)
		if err != nil {
			return open(original)
		}
		closeBridge = cleanup
		return open(bridge)
	}
	return flow.GetIDToken(provider, cfg)
}

func googleLoginURL(ctx context.Context, transport http.RoundTripper, original, hint string) (string, error) {
	u, err := url.Parse(original)
	if err != nil {
		return "", err
	}
	if hint == "" || u.Scheme != "https" || u.Host != "oauth2.sigstore.dev" || u.User != nil ||
		u.Query().Get("connector_id") != oauthflow.PublicInstanceGoogleAuthSubURL {
		return original, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	for range 5 {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return "", err
		}
		resp, err := client.Do(req)
		if err != nil {
			return "", err
		}
		resp.Body.Close() // nolint:errcheck
		switch resp.StatusCode {
		case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		default:
			return "", fmt.Errorf("unexpected authorization response: %d", resp.StatusCode)
		}
		u, err = resp.Location()
		if err != nil {
			return "", err
		}
		if u.Scheme != "https" || u.User != nil {
			return "", fmt.Errorf("unexpected authorization redirect")
		}
		switch u.Host {
		case "accounts.google.com":
			q := u.Query()
			q.Set("login_hint", hint)
			u.RawQuery = q.Encode()
			return u.String(), nil
		case "oauth2.sigstore.dev":
		default:
			return "", fmt.Errorf("unexpected authorization host")
		}
	}
	return "", fmt.Errorf("too many authorization redirects")
}

func loginHintBridge(original, target string) (string, func(), error) {
	u, err := url.Parse(original)
	if err != nil {
		return "", nil, err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	path := "/" + rand.Text()
	server := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != path {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Referrer-Policy", "no-referrer")
			http.Redirect(w, r, target, http.StatusFound)
		}),
	}
	go func() { _ = server.Serve(listener) }()
	// Expose both loopback ports to SSH browser relays without changing Google's callback.
	bridge := &url.URL{Scheme: "http", Host: listener.Addr().String(), Path: path}
	bridge.RawQuery = url.Values{"redirect_uri": {u.Query().Get("redirect_uri")}}.Encode()
	return bridge.String(), func() { _ = server.Close() }, nil
}
