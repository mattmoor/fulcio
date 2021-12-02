//
// Copyright 2021 The Sigstore Authors.
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

package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path"
)

type CertificateResponse struct {
	CertPEM  []byte
	ChainPEM []byte
	SCT      []byte
}

// SigstorePublicServerURL is the URL of Sigstore's public Fulcio service.
const SigstorePublicServerURL = "https://fulcio.sigstore.dev"

// Client is the interface for accessing the Fulcio API.
type Client interface {
	// SigningCert sends the provided CertificateRequest to the /api/v1/singingCert
	// endpoint of a Fulcio API, authenticated with the provided bearer token.
	SigningCert(cr CertificateRequest, token string) (*CertificateResponse, error)
}

// NewClient creates a new Fulcio API client talking to the provided URL.
func NewClient(url *url.URL) Client {
	return &client{
		baseURL: url,
		client:  http.DefaultClient,
	}
}

type client struct {
	baseURL *url.URL
	client  *http.Client
}

var _ Client = (*client)(nil)

// SigningCert implements Client
func (c *client) SigningCert(cr CertificateRequest, token string) (*CertificateResponse, error) {
	// Construct the API endpoint for this handler
	endpoint := *c.baseURL
	endpoint.Path = path.Join(endpoint.Path, signingCertPath)

	b, err := json.Marshal(cr)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, endpoint.String(), bytes.NewBuffer(b))
	if err != nil {
		return nil, err
	}
	// Set the authorization header to our OIDC bearer token.
	req.Header.Set("Authorization", "Bearer "+token)
	// Set the content-type to reflect we're sending JSON.
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// The API should return a 201 Created on success.  If we see anything else,
	// then turn the response body into an error.
	if resp.StatusCode != http.StatusCreated {
		return nil, errors.New(string(body))
	}

	// Extract the SCT from the response header.
	sct, err := base64.StdEncoding.DecodeString(resp.Header.Get("SCT"))
	if err != nil {
		return nil, err
	}

	// Split the cert and the chain
	certBlock, chainPem := pem.Decode(body)
	certPem := pem.EncodeToMemory(certBlock)
	return &CertificateResponse{
		CertPEM:  certPem,
		ChainPEM: chainPem,
		SCT:      sct,
	}, nil
}
