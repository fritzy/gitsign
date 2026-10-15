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
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"net/rpc"
	"time"

	"github.com/sigstore/gitsign/internal/cache/api"
	"github.com/sigstore/gitsign/internal/config"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

type Client struct {
	Client        *rpc.Client
	Roots         *x509.CertPool
	Intermediates *x509.CertPool
}

func (c *Client) GetCredentials(ctx context.Context, cfg *config.Config) (crypto.PrivateKey, []byte, []byte, error) {
	id, err := CredentialID(cfg)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error getting credential ID: %w", err)
	}
	resp := new(api.Credential)
	if err := c.call(ctx, "Service.GetCredential", api.GetCredentialRequest{ID: id}, resp); err != nil {
		return nil, nil, nil, err
	}

	privateKey, err := cryptoutils.UnmarshalPEMToPrivateKey(resp.PrivateKey, cryptoutils.SkipPassword)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error unmarshalling private key: %w", err)
	}

	// Check that the cert is in fact still valid.
	certs, err := cryptoutils.UnmarshalCertificatesFromPEM(resp.Cert)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error unmarshalling cert: %w", err)
	}
	// There should really only be 1 cert, but check them all anyway.
	for _, cert := range certs {
		if len(cert.UnhandledCriticalExtensions) > 0 {
			var unhandledExts []asn1.ObjectIdentifier
			for _, oid := range cert.UnhandledCriticalExtensions {
				if !oid.Equal(cryptoutils.SANOID) {
					unhandledExts = append(unhandledExts, oid)
				}
			}

			cert.UnhandledCriticalExtensions = unhandledExts
		}

		if _, err := cert.Verify(x509.VerifyOptions{
			Roots:         c.Roots,
			Intermediates: c.Intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			// We're going to be using this key immediately, so we don't need a long window.
			// Just make sure it's not about to expire.
			CurrentTime: time.Now().Add(30 * time.Second),
		}); err != nil {
			return nil, nil, nil, fmt.Errorf("stored cert no longer valid: %w", err)
		}
	}

	return privateKey, resp.Cert, resp.Chain, nil
}

func (c *Client) StoreCert(ctx context.Context, cfg *config.Config, priv crypto.PrivateKey, cert, chain []byte) error {
	id, err := CredentialID(cfg)
	if err != nil {
		return fmt.Errorf("error getting credential ID: %w", err)
	}
	privPEM, err := cryptoutils.MarshalPrivateKeyToPEM(priv)
	if err != nil {
		return err
	}

	if err := c.call(ctx, "Service.StoreCredential", api.StoreCredentialRequest{
		ID: id,
		Credential: &api.Credential{
			PrivateKey: privPEM,
			Cert:       cert,
			Chain:      chain,
		},
	}, new(api.Credential)); err != nil {
		return err
	}

	return err
}

// CredentialID groups credentials by configured identity and certificate issuer.
func CredentialID(cfg *config.Config) (string, error) {
	if cfg == nil {
		return "", fmt.Errorf("missing signing configuration")
	}
	data, err := json.Marshal([]string{
		cfg.CommitterEmail, cfg.Issuer, cfg.ClientID, cfg.ConnectorID,
		cfg.Fulcio, cfg.FulcioRoot, cfg.TokenProvider,
	})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("identity-v1:%x", sha256.Sum256(data)), nil
}

const requestTimeout = 5 * time.Second

func (c *Client) call(ctx context.Context, method string, args, reply any) error {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- c.Client.Call(method, args, reply) }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		// Release the pending RPC and reject subsequent calls on the stalled connection.
		_ = c.Client.Close()
		return ctx.Err()
	}
}
