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
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/sigstore/gitsign/internal/cache"
	"github.com/sigstore/gitsign/internal/cache/api"
	"github.com/sigstore/gitsign/internal/cache/service"
	"github.com/sigstore/gitsign/internal/config"
	"github.com/sigstore/gitsign/internal/fulcio"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

type identityFactory interface {
	NewIdentity(context.Context, *config.Config) (*fulcio.Identity, error)
}

func primeRepositories(ctx context.Context, s *service.Service, repos []string, factory identityFactory) (err error) {
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	// Run before serving RPCs; config files and opener commands may use relative paths.
	defer func() { err = errors.Join(err, os.Chdir(wd)) }()
	seen := make(map[string]bool)
	for _, repo := range repos {
		if !filepath.IsAbs(repo) {
			repo = filepath.Join(wd, repo)
		}
		if err := os.Chdir(repo); err != nil {
			return fmt.Errorf("%s: %w", repo, err)
		}
		if err := exec.CommandContext(ctx, "git", "rev-parse", "--git-dir").Run(); err != nil {
			return fmt.Errorf("%s: not a Git repository: %w", repo, err)
		}
		cfg, err := config.Get()
		if err != nil {
			return fmt.Errorf("%s: %w", repo, err)
		}
		id, err := cache.CredentialID(cfg)
		if err != nil {
			return err
		}
		if seen[id] {
			continue
		}
		identity, err := factory.NewIdentity(ctx, cfg)
		if err != nil {
			return fmt.Errorf("%s: %w", repo, err)
		}
		privateKey, err := cryptoutils.MarshalPrivateKeyToPEM(identity.PrivateKey)
		if err != nil {
			return err
		}
		if err := s.StoreCredential(api.StoreCredentialRequest{
			ID: id, Credential: &api.Credential{PrivateKey: privateKey, Cert: identity.CertPEM, Chain: identity.ChainPEM},
		}, new(api.Credential)); err != nil {
			return err
		}
		seen[id] = true
		log.Printf("primed credentials for %s", repo)
	}
	return nil
}
