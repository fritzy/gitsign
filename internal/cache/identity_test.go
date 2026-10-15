// Copyright 2022 The Sigstore Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cache_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/rpc"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/github/smimesign/fakeca"
	"github.com/sigstore/gitsign/internal/cache"
	"github.com/sigstore/gitsign/internal/cache/api"
	"github.com/sigstore/gitsign/internal/cache/service"
	"github.com/sigstore/gitsign/internal/config"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func TestCacheAcrossWorktrees(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() { serverConn.Close(); clientConn.Close() })
	server := rpc.NewServer()
	if err := server.Register(service.NewService()); err != nil {
		t.Fatal(err)
	}
	go server.ServeConn(serverConn)
	ca := fakeca.New()
	client := &cache.Client{Client: rpc.NewClient(clientConn), Roots: ca.ChainPool()}
	defer client.Client.Close()
	cfg := &config.Config{CommitterEmail: "alice@example.com", Issuer: "https://issuer.example.com"}
	cert, err := cryptoutils.MarshalCertificateToPEM(ca.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := client.StoreCert(ctx, cfg, ca.PrivateKey, cert, nil); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	t.Chdir(root)
	for i := range 50 {
		dir := filepath.Join(root, fmt.Sprintf("worktree-%d", i))
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chdir(dir); err != nil {
			t.Fatal(err)
		}
		key, got, _, err := client.GetCredentials(ctx, cfg)
		if err != nil {
			t.Fatalf("worktree %d: %v", i, err)
		}
		if key == nil || string(got) != string(cert) {
			t.Fatalf("worktree %d: wrong credential", i)
		}
		if err := os.Chdir(root); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(dir); err != nil {
			t.Fatal(err)
		}
	}
	other := *cfg
	other.CommitterEmail = "bob@example.com"
	if _, _, _, err := client.GetCredentials(ctx, &other); err == nil {
		t.Fatal("different identity reused cached credentials")
	}
}

func TestCredentialIDIsolation(t *testing.T) {
	base := config.Config{CommitterEmail: "alice@example.com", Issuer: "https://issuer.example.com", Fulcio: "https://fulcio.example.com", ClientID: "sigstore"}
	id, err := cache.CredentialID(&base)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*config.Config){
		"email":      func(c *config.Config) { c.CommitterEmail = "bob@example.com" },
		"issuer":     func(c *config.Config) { c.Issuer = "https://other.example.com" },
		"fulcio":     func(c *config.Config) { c.Fulcio = "https://other.example.com" },
		"root":       func(c *config.Config) { c.FulcioRoot = "/other/root.pem" },
		"client":     func(c *config.Config) { c.ClientID = "other" },
		"login hint": func(c *config.Config) { c.LoginHint = "other@example.com" },
		"connector":  func(c *config.Config) { c.ConnectorID = "other" },
		"provider":   func(c *config.Config) { c.TokenProvider = "interactive" },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := base
			change(&cfg)
			got, err := cache.CredentialID(&cfg)
			if err != nil {
				t.Fatal(err)
			}
			if got == id {
				t.Fatal("different signing configuration shared a cache key")
			}
		})
	}
	base.CredentialCache = "/another/cache.sock"
	base.URLOpener = "other-browser {{.URL}}"
	base.Rekor = "https://other-rekor.example.com"
	base.CommitterName = "Different display name"
	got, err := cache.CredentialID(&base)
	if err != nil {
		t.Fatal(err)
	}
	if got != id {
		t.Fatal("non-identity settings changed the cache key")
	}
}

func TestCacheRequestCancellation(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	client := &cache.Client{Client: rpc.NewClient(clientConn)}
	defer client.Client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	// The peer neither reads the request nor sends a reply.
	done := make(chan error, 1)
	go func() {
		_, _, _, err := client.GetCredentials(ctx, &config.Config{})
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cache request ignored cancellation")
	}
}

func TestCacheRefreshReplacesCredential(t *testing.T) {
	s := service.NewService()
	for _, value := range []string{"old", "renewed"} {
		if err := s.StoreCredential(api.StoreCredentialRequest{ID: "identity", Credential: &api.Credential{Cert: []byte(value)}}, new(api.Credential)); err != nil {
			t.Fatal(err)
		}
	}
	var got api.Credential
	if err := s.GetCredential(api.GetCredentialRequest{ID: "identity"}, &got); err != nil {
		t.Fatal(err)
	}
	if string(got.Cert) != "renewed" {
		t.Fatal("cache retained the previous credential")
	}
}
