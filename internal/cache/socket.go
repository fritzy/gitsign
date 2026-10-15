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

package cache

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/rpc"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// DefaultSocketPath is shared by the daemon and automatic client discovery.
func DefaultSocketPath() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "sigstore", "gitsign", "cache.sock"), nil
}

// Connect returns nil when caching is disabled or the automatic socket is absent.
func Connect(ctx context.Context, setting string) (*rpc.Client, error) {
	if setting == "" || strings.EqualFold(setting, "false") {
		return nil, nil
	}
	automatic := strings.EqualFold(setting, "auto") || strings.EqualFold(setting, "true")
	var path string
	var err error
	if automatic {
		path, err = DefaultSocketPath()
	} else {
		path, err = filepath.Abs(setting)
	}
	if err != nil {
		return nil, fmt.Errorf("resolving cache socket: %w", err)
	}
	conn, err := (&net.Dialer{Timeout: requestTimeout}).DialContext(ctx, "unix", path)
	if err != nil {
		if automatic && (errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED)) {
			return nil, nil
		}
		return nil, fmt.Errorf("connecting to cache socket %q: %w", path, err)
	}
	return rpc.NewClient(conn), nil
}
