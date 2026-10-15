//
// Copyright 2022 The Sigstore Authors.
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
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/sigstore/gitsign/internal/config"
)

func TestUnavailableCacheFallsBackToAuthentication(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CACHE_HOME", dir)
	t.Setenv("LocalAppData", dir)
	var requests atomic.Int32
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(w, "foreground authentication reached", http.StatusInternalServerError)
	}))
	defer issuer.Close()
	for _, setting := range []string{"auto", filepath.Join(dir, "missing.sock"), "false"} {
		requests.Store(0)
		var output bytes.Buffer
		_, err := NewIdentity(context.Background(), &config.Config{
			CredentialCache: setting, Issuer: issuer.URL, TokenProvider: "interactive",
		}, strings.NewReader(""), &output)
		if err == nil || !strings.Contains(err.Error(), "foreground authentication reached") {
			t.Fatalf("setting %q: error = %v", setting, err)
		}
		if requests.Load() != 1 {
			t.Fatalf("setting %q: foreground login was not attempted", setting)
		}
		if setting == "auto" && strings.Contains(output.String(), "error connecting") {
			t.Fatal("absent automatic cache emitted an error")
		}
	}
}
