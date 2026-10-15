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

package service

import (
	"fmt"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/sigstore/gitsign/internal/cache/api"
)

type Service struct {
	store *cache.Cache
}

const (
	defaultExpiration = 10 * time.Minute
	cleanupInterval   = 1 * time.Minute
)

func NewService() *Service {
	s := &Service{
		store: cache.New(defaultExpiration, cleanupInterval),
	}
	return s
}

func (s *Service) StoreCredential(req api.StoreCredentialRequest, resp *api.Credential) error {
	fmt.Println("Store", req.ID)
	s.store.Set(req.ID, req.Credential, defaultExpiration)
	*resp = *req.Credential
	return nil
}

func (s *Service) GetCredential(req api.GetCredentialRequest, resp *api.Credential) error {
	fmt.Println("Get", req.ID)
	i, ok := s.store.Get(req.ID)
	if ok {
		fmt.Println("gitsign-credential-cache: found credential!")
		cred, ok := i.(*api.Credential)
		if !ok {
			return fmt.Errorf("unknown credential type %T", i)
		}
		*resp = *cred
		return nil
	}

	// Authentication belongs to the foreground signer, never the RPC server.
	return fmt.Errorf("%q not found", req.ID)
}
