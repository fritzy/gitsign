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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sigstore/gitsign/internal/cache/api"
	"github.com/sigstore/gitsign/internal/config"
)

func TestCacheMissDoesNotAuthenticate(t *testing.T) {
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("cache miss attempted authentication")
		http.Error(w, "unexpected authentication", http.StatusInternalServerError)
	}))
	defer issuer.Close()
	s := NewService()
	req := api.GetCredentialRequest{ID: "missing", Config: &config.Config{
		Issuer: issuer.URL, TokenProvider: "interactive",
	}}
	err := s.GetCredential(req, new(api.Credential))
	if err == nil || err.Error() != `"missing" not found` {
		t.Fatalf("GetCredential = %v, want cache miss", err)
	}
}
