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

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/github/smimesign/fakeca"
	"github.com/sigstore/gitsign/internal/cache"
	"github.com/sigstore/gitsign/internal/cache/api"
	"github.com/sigstore/gitsign/internal/cache/service"
	"github.com/sigstore/gitsign/internal/config"
	"github.com/sigstore/gitsign/internal/fulcio"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

type fakeIdentityFactory struct {
	calls    []*config.Config
	identity *fulcio.Identity
	err      error
}

func (f *fakeIdentityFactory) NewIdentity(_ context.Context, cfg *config.Config) (*fulcio.Identity, error) {
	f.calls = append(f.calls, cfg)
	return f.identity, f.err
}

func initRepo(t *testing.T, path, email string) {
	t.Helper()
	for _, args := range [][]string{{"init", path}, {"-C", path, "config", "user.email", email}} {
		if out, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
}

func TestPrimeRepositories(t *testing.T) {
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	root := t.TempDir()
	t.Chdir(root)
	initRepo(t, "first", "alice@example.com")
	initRepo(t, "second", "alice@example.com")
	initRepo(t, "third", "bob@example.com")
	ca := fakeca.New()
	cert, err := cryptoutils.MarshalCertificateToPEM(ca.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	factory := &fakeIdentityFactory{identity: &fulcio.Identity{PrivateKey: ca.PrivateKey, CertPEM: cert}}
	s := service.NewService()
	if err := primeRepositories(context.Background(), s, []string{"first", "second", "third"}, factory); err != nil {
		t.Fatal(err)
	}
	if len(factory.calls) != 2 {
		t.Fatalf("authenticated %d times, want 2 distinct identities", len(factory.calls))
	}
	for _, cfg := range factory.calls {
		id, err := cache.CredentialID(cfg)
		if err != nil {
			t.Fatal(err)
		}
		var got api.Credential
		if err := s.GetCredential(api.GetCredentialRequest{ID: id}, &got); err != nil {
			t.Fatal(err)
		}
		if len(got.PrivateKey) == 0 || string(got.Cert) != string(cert) {
			t.Fatal("primed credential was not stored")
		}
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if wd != root {
		t.Fatalf("working directory = %s, want %s", wd, root)
	}
}

func TestPrimeFailureRestoresDirectory(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	initRepo(t, "repo", "alice@example.com")
	authErr := errors.New("login failed")
	factory := &fakeIdentityFactory{err: authErr}
	if err := primeRepositories(context.Background(), service.NewService(), []string{"repo"}, factory); !errors.Is(err, authErr) {
		t.Fatalf("error = %v", err)
	}
	wd, err := os.Getwd()
	if err != nil || wd != root {
		t.Fatalf("working directory = %s, error = %v", wd, err)
	}
}

func TestPrimeRejectsNonRepository(t *testing.T) {
	root := t.TempDir()
	factory := &fakeIdentityFactory{}
	for _, path := range []string{root, filepath.Join(root, "missing")} {
		if err := primeRepositories(context.Background(), service.NewService(), []string{path}, factory); err == nil {
			t.Fatalf("accepted %s", path)
		}
	}
	if len(factory.calls) != 0 {
		t.Fatal("authenticated without a repository")
	}
}
