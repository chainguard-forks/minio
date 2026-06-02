// Copyright (c) 2015-2022 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package openid

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/chainguard-forks/minio/internal/arn"
	"github.com/chainguard-forks/minio/internal/config"
	jwtm "github.com/chainguard-forks/minio/internal/jwt"
	jwtgo "github.com/golang-jwt/jwt/v4"
	xnet "github.com/minio/pkg/v3/net"
)

func TestUpdateClaimsExpiry(t *testing.T) {
	testCases := []struct {
		exp             any
		dsecs           string
		expectedFailure bool
	}{
		{"", "", true},
		{"-1", "0", true},
		{"-1", "900", true},
		{"1574812326", "900", false},
		{1574812326, "900", false},
		{int64(1574812326), "900", false},
		{int(1574812326), "900", false},
		{uint(1574812326), "900", false},
		{uint64(1574812326), "900", false},
		{json.Number("1574812326"), "900", false},
		{1574812326.000, "900", false},
		{time.Duration(3) * time.Minute, "900", false},
	}

	for _, testCase := range testCases {
		t.Run("", func(t *testing.T) {
			claims := map[string]any{}
			claims["exp"] = testCase.exp
			err := updateClaimsExpiry(testCase.dsecs, claims)
			if err != nil && !testCase.expectedFailure {
				t.Errorf("Expected success, got failure %s", err)
			}
			if err == nil && testCase.expectedFailure {
				t.Error("Expected failure, got success")
			}
		})
	}
}

// jwksRSA is a sample JWKS document containing a single RSA public key with
// kid "2011-04-29".
const jwksRSA = `{"keys":
       [
         {"kty":"RSA",
          "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
          "e":"AQAB",
          "alg":"RS256",
          "kid":"2011-04-29"}
       ]
     }`

func initJWKSServer() *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(jwksRSA))
	}))
	return server
}

func TestJWTHMACType(t *testing.T) {
	server := initJWKSServer()
	defer server.Close()

	jwt := &jwtgo.Token{
		Method: jwtgo.SigningMethodHS256,
		Claims: jwtgo.StandardClaims{
			ExpiresAt: 253428928061,
			Audience:  "76b95ae5-33ef-4283-97b7-d2a85dc2d8f4",
		},
		Header: map[string]any{
			"typ": "JWT",
			"alg": jwtgo.SigningMethodHS256.Alg(),
			"kid": "76b95ae5-33ef-4283-97b7-d2a85dc2d8f4",
		},
	}

	token, err := jwt.SignedString([]byte("WNGvKVyyNmXq0TraSvjaDN9CtpFgx35IXtGEffMCPR0"))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(token)

	u1, err := xnet.ParseHTTPURL(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	pubKeys := publicKeys{
		RWMutex: &sync.RWMutex{},
		pkMap:   map[string]any{},
	}
	pubKeys.add("76b95ae5-33ef-4283-97b7-d2a85dc2d8f4", []byte("WNGvKVyyNmXq0TraSvjaDN9CtpFgx35IXtGEffMCPR0"))

	if len(pubKeys.pkMap) != 1 {
		t.Fatalf("Expected 1 keys, got %d", len(pubKeys.pkMap))
	}

	provider := providerCfg{
		ClientID:     "76b95ae5-33ef-4283-97b7-d2a85dc2d8f4",
		ClientSecret: "WNGvKVyyNmXq0TraSvjaDN9CtpFgx35IXtGEffMCPR0",
		// A symmetric (HMAC) IdP advertises an HS* id_token signing algorithm in
		// its discovery document. Required after the CVE-2026-33322 fix for the
		// ClientSecret to be honoured as an HMAC verification key.
		DiscoveryDoc: DiscoveryDoc{
			IDTokenSigningAlgValuesSupported: []string{"HS256"},
		},
	}
	provider.JWKS.URL = u1
	cfg := Config{
		Enabled: true,
		pubKeys: pubKeys,
		arnProviderCfgsMap: map[arn.ARN]*providerCfg{
			DummyRoleARN: &provider,
		},
		ProviderCfgs: map[string]*providerCfg{
			"1": &provider,
		},
		closeRespFn: func(rc io.ReadCloser) {
			rc.Close()
		},
	}

	var claims jwtgo.MapClaims
	if err = cfg.Validate(t.Context(), DummyRoleARN, token, "", "", claims); err != nil {
		t.Fatal(err)
	}
}

// TestJWTAlgConfusion is a regression test for CVE-2026-33322 /
// GHSA-5cx5-wh4m-82fh (JWT algorithm confusion in OIDC auth).
//
// When an asymmetric IdP signing key is configured (via JWKS), an attacker who
// knows the ClientSecret must NOT be able to forge a token of the shape
// {"alg":"HS256","kid":"<ClientID>"} signed with the ClientSecret and have it
// accepted. We also assert that a legitimate RSA-signed token continues to
// validate, and that a genuine symmetric (HMAC) setup still works.
func TestJWTAlgConfusion(t *testing.T) {
	server := initJWKSServer() // serves an RSA key with kid "2011-04-29"
	defer server.Close()

	u1, err := xnet.ParseHTTPURL(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	const clientID = "76b95ae5-33ef-4283-97b7-d2a85dc2d8f4"
	const clientSecret = "WNGvKVyyNmXq0TraSvjaDN9CtpFgx35IXtGEffMCPR0"

	// newCfg builds a Config for a provider. algs is what the IdP's discovery
	// document advertises as its id_token signing algorithms. The ClientSecret
	// is registered as an HMAC key under the ClientID exactly like
	// PopulatePublicKey does, and the asymmetric JWKS key (kid "2011-04-29") is
	// loaded, mirroring a real deployment where both live in the same key map.
	newCfg := func(algs ...string) (Config, *rsa.PrivateKey) {
		pubKeys := publicKeys{
			RWMutex: &sync.RWMutex{},
			pkMap:   map[string]any{},
		}
		pubKeys.add(clientID, []byte(clientSecret))
		if err := pubKeys.parseAndAdd(bytes.NewBufferString(jwksRSA)); err != nil {
			t.Fatalf("Error loading pubkeys: %v", err)
		}
		// Add a fresh RSA key we control under a known kid so we can mint
		// genuinely IdP-signed RS256 tokens.
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		pubKeys.add("rs-test-kid", &privKey.PublicKey)

		provider := providerCfg{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			DiscoveryDoc: DiscoveryDoc{
				IDTokenSigningAlgValuesSupported: algs,
			},
		}
		provider.JWKS.URL = u1
		return Config{
			Enabled: true,
			pubKeys: pubKeys,
			arnProviderCfgsMap: map[arn.ARN]*providerCfg{
				DummyRoleARN: &provider,
			},
			ProviderCfgs: map[string]*providerCfg{
				"1": &provider,
			},
			closeRespFn: func(rc io.ReadCloser) { rc.Close() },
		}, privKey
	}

	// (a) THE EXPLOIT. Asymmetric IdP (advertises only RS256). Attacker who
	// knows the ClientSecret forges {"alg":"HS256","kid":"<ClientID>"} and signs
	// it with the ClientSecret. Pre-fix this verified against the HMAC key
	// registered under the ClientID and was accepted. It MUST now be rejected.
	t.Run("exploit-hs256-kid-clientID", func(t *testing.T) {
		cfg, _ := newCfg("RS256")
		tok := jwtgo.New(jwtgo.SigningMethodHS256)
		tok.Header["kid"] = clientID
		tok.Claims = jwtgo.MapClaims{
			"exp": time.Now().Add(time.Hour).Unix(),
			"aud": clientID,
		}
		signed, err := tok.SignedString([]byte(clientSecret))
		if err != nil {
			t.Fatal(err)
		}
		var claims jwtgo.MapClaims
		if err := cfg.Validate(t.Context(), DummyRoleARN, signed, "", "", claims); err == nil {
			t.Fatal("SECURITY: forged HS256 token (kid=ClientID, signed with ClientSecret) was ACCEPTED against an asymmetric IdP")
		}
	})

	// (a2) Variant: attacker targets the asymmetric JWKS kid with an HS256 alg.
	// Must also be rejected (key-type/alg binding in the keyfunc).
	t.Run("exploit-hs256-kid-asymmetric", func(t *testing.T) {
		cfg, _ := newCfg("RS256")
		tok := jwtgo.New(jwtgo.SigningMethodHS256)
		tok.Header["kid"] = "2011-04-29"
		tok.Claims = jwtgo.MapClaims{
			"exp": time.Now().Add(time.Hour).Unix(),
			"aud": clientID,
		}
		signed, err := tok.SignedString([]byte(clientSecret))
		if err != nil {
			t.Fatal(err)
		}
		var claims jwtgo.MapClaims
		if err := cfg.Validate(t.Context(), DummyRoleARN, signed, "", "", claims); err == nil {
			t.Fatal("SECURITY: HS256 token with asymmetric kid was accepted")
		}
	})

	// (b) Legitimate RSA-signed token (the normal path for an asymmetric IdP)
	// still validates.
	t.Run("legitimate-rs256", func(t *testing.T) {
		cfg, privKey := newCfg("RS256")
		tok := jwtgo.New(jwtgo.SigningMethodRS256)
		tok.Header["kid"] = "rs-test-kid"
		tok.Claims = jwtgo.MapClaims{
			"exp": time.Now().Add(time.Hour).Unix(),
			"aud": clientID,
		}
		signed, err := tok.SignedString(privKey)
		if err != nil {
			t.Fatal(err)
		}
		var claims jwtgo.MapClaims
		if err := cfg.Validate(t.Context(), DummyRoleARN, signed, "", "", claims); err != nil {
			t.Fatalf("legitimate RS256 token rejected: %v", err)
		}
	})

	// (c) Genuine symmetric (HMAC) deployment: the IdP advertises HS256, so an
	// HS256 token whose kid resolves to the HMAC secret must still validate.
	t.Run("legitimate-hs256", func(t *testing.T) {
		cfg, _ := newCfg("HS256")
		tok := jwtgo.New(jwtgo.SigningMethodHS256)
		tok.Header["kid"] = clientID
		tok.Claims = jwtgo.MapClaims{
			"exp": time.Now().Add(time.Hour).Unix(),
			"aud": clientID,
		}
		signed, err := tok.SignedString([]byte(clientSecret))
		if err != nil {
			t.Fatal(err)
		}
		var claims jwtgo.MapClaims
		if err := cfg.Validate(t.Context(), DummyRoleARN, signed, "", "", claims); err != nil {
			t.Fatalf("legitimate HS256 token rejected: %v", err)
		}
	})
}

func TestJWT(t *testing.T) {
	const jsonkey = `{"keys":
       [
         {"kty":"RSA",
          "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
          "e":"AQAB",
          "alg":"RS256",
          "kid":"2011-04-29"}
       ]
     }`

	pubKeys := publicKeys{
		RWMutex: &sync.RWMutex{},
		pkMap:   map[string]any{},
	}
	err := pubKeys.parseAndAdd(bytes.NewBuffer([]byte(jsonkey)))
	if err != nil {
		t.Fatal("Error loading pubkeys:", err)
	}
	if len(pubKeys.pkMap) != 1 {
		t.Fatalf("Expected 1 keys, got %d", len(pubKeys.pkMap))
	}

	u1, err := xnet.ParseHTTPURL("http://127.0.0.1:8443")
	if err != nil {
		t.Fatal(err)
	}

	provider := providerCfg{}
	provider.JWKS.URL = u1
	cfg := Config{
		Enabled: true,
		pubKeys: pubKeys,
		arnProviderCfgsMap: map[arn.ARN]*providerCfg{
			DummyRoleARN: &provider,
		},
		ProviderCfgs: map[string]*providerCfg{
			"1": &provider,
		},
	}

	u, err := url.Parse("http://127.0.0.1:8443/?Token=invalid")
	if err != nil {
		t.Fatal(err)
	}

	var claims jwtgo.MapClaims
	if err = cfg.Validate(t.Context(), DummyRoleARN, u.Query().Get("Token"), "", "", claims); err == nil {
		t.Fatal(err)
	}
}

func TestDefaultExpiryDuration(t *testing.T) {
	testCases := []struct {
		reqURL    string
		duration  time.Duration
		expectErr bool
	}{
		{
			reqURL:   "http://127.0.0.1:8443/?Token=xxxxx",
			duration: time.Duration(60) * time.Minute,
		},
		{
			reqURL:    "http://127.0.0.1:8443/?DurationSeconds=9s",
			expectErr: true,
		},
		{
			reqURL:    "http://127.0.0.1:8443/?DurationSeconds=31536001",
			expectErr: true,
		},
		{
			reqURL:    "http://127.0.0.1:8443/?DurationSeconds=800",
			expectErr: true,
		},
		{
			reqURL:   "http://127.0.0.1:8443/?DurationSeconds=901",
			duration: time.Duration(901) * time.Second,
		},
	}

	for i, testCase := range testCases {
		u, err := url.Parse(testCase.reqURL)
		if err != nil {
			t.Fatal(err)
		}
		d, err := GetDefaultExpiration(u.Query().Get("DurationSeconds"))
		gotErr := (err != nil)
		if testCase.expectErr != gotErr {
			t.Errorf("Test %d: Expected %v, got %v with error %s", i+1, testCase.expectErr, gotErr, err)
		}
		if d != testCase.duration {
			t.Errorf("Test %d: Expected duration %d, got %d", i+1, testCase.duration, d)
		}
	}
}

func TestExpCorrect(t *testing.T) {
	signKey, _ := base64.StdEncoding.DecodeString("NTNv7j0TuYARvmNMmWXo6fKvM4o6nv/aUi9ryX38ZH+L1bkrnD1ObOQ8JAUmHCBq7Iy7otZcyAagBLHVKvvYaIpmMuxmARQ97jUVG16Jkpkp1wXOPsrF9zwew6TpczyHkHgX5EuLg2MeBuiT/qJACs1J0apruOOJCg/gOtkjB4c=")

	claimsMap := jwtm.NewMapClaims()
	claimsMap.SetExpiry(time.Now().Add(time.Minute))
	claimsMap.SetAccessKey("test-access")
	if err := updateClaimsExpiry("3600", claimsMap.MapClaims); err != nil {
		t.Error(err)
	}
	// Build simple token with updated expiration claim
	token := jwtgo.NewWithClaims(jwtgo.SigningMethodHS256, claimsMap)
	tokenString, err := token.SignedString(signKey)
	if err != nil {
		t.Error(err)
	}

	// Parse token to be sure it is valid
	err = jwtm.ParseWithClaims(tokenString, claimsMap, func(*jwtm.MapClaims) ([]byte, error) {
		return signKey, nil
	})
	if err != nil {
		t.Error(err)
	}
}

func TestKeycloakProviderInitialization(t *testing.T) {
	testConfig := providerCfg{
		DiscoveryDoc: DiscoveryDoc{
			TokenEndpoint: "http://keycloak.test/token/endpoint",
		},
	}
	testKvs := config.KVS{}
	testKvs.Set(Vendor, "keycloak")
	testKvs.Set(KeyCloakRealm, "TestRealm")
	testKvs.Set(KeyCloakAdminURL, "http://keycloak.test/auth/admin")
	cfgGet := func(param string) string {
		return testKvs.Get(param)
	}

	if testConfig.provider != nil {
		t.Errorf("Empty config cannot have any provider!")
	}

	if err := testConfig.initializeProvider(cfgGet, http.DefaultTransport); err != nil {
		t.Error(err)
	}

	if testConfig.provider == nil {
		t.Errorf("keycloak provider must be initialized!")
	}
}
