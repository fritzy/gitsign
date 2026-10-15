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
	"net"
	"net/rpc"
	"os"
	"path/filepath"
	"testing"

	"github.com/sigstore/gitsign/internal/cache"
	"github.com/sigstore/gitsign/internal/cache/api"
	"github.com/sigstore/gitsign/internal/cache/service"
)

func defaultSocket(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CACHE_HOME", dir)
	t.Setenv("LocalAppData", dir)
	path, err := cache.DefaultSocketPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAutomaticCacheDiscovery(t *testing.T) {
	path := defaultSocket(t)
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := rpc.NewServer()
	if err := server.Register(service.NewService()); err != nil {
		t.Fatal(err)
	}
	go server.Accept(listener)
	for _, setting := range []string{"auto", "true", path} {
		client, err := cache.Connect(context.Background(), setting)
		if err != nil || client == nil {
			t.Fatalf("Connect(%q) = %v, %v", setting, client, err)
		}
		err = client.Call("Service.GetCredential", api.GetCredentialRequest{ID: "probe"}, new(api.Credential))
		client.Close()
		if err == nil || err.Error() != `"probe" not found` {
			t.Fatalf("RPC did not reach the cache: %v", err)
		}
	}
	for _, setting := range []string{"", "false"} {
		client, err := cache.Connect(context.Background(), setting)
		if err != nil || client != nil {
			t.Fatalf("Connect(%q) = %v, %v", setting, client, err)
		}
	}
}

func TestAutomaticCacheAbsentOrStale(t *testing.T) {
	path := defaultSocket(t)
	checkAbsent := func() {
		t.Helper()
		client, err := cache.Connect(context.Background(), "auto")
		if err != nil || client != nil {
			t.Fatalf("Connect(auto) = %v, %v", client, err)
		}
	}
	checkAbsent()
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	listener.Close()
	checkAbsent()
	if _, err := cache.Connect(context.Background(), path); err == nil {
		t.Fatal("an explicit unavailable socket should report an error")
	}
}
