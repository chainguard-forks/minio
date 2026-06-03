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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/chainguard-forks/minio/internal/arn"
	"github.com/chainguard-forks/minio/internal/auth"
	jwtgo "github.com/golang-jwt/jwt/v4"
	xnet "github.com/minio/pkg/v3/net"
	"github.com/minio/pkg/v3/policy"
)

type publicKeys struct {
	*sync.RWMutex

	// map of kid to public key
	pkMap map[string]any
}

func (pk *publicKeys) parseAndAdd(b io.Reader) error {
	var jwk JWKS
	err := json.NewDecoder(b).Decode(&jwk)
	if err != nil {
		return err
	}

	for _, key := range jwk.Keys {
		pkey, err := key.DecodePublicKey()
		if err != nil {
			return err
		}
		pk.add(key.Kid, pkey)
	}

	return nil
}

func (pk *publicKeys) add(keyID string, key any) {
	pk.Lock()
	defer pk.Unlock()

	pk.pkMap[keyID] = key
}

func (pk *publicKeys) get(kid string) any {
	pk.RLock()
	defer pk.RUnlock()
	return pk.pkMap[kid]
}

// PopulatePublicKey - populates a new publickey from the JWKS URL.
func (r *Config) PopulatePublicKey(arn arn.ARN) error {
	pCfg := r.arnProviderCfgsMap[arn]
	if pCfg.JWKS.URL == nil || pCfg.JWKS.URL.String() == "" {
		return nil
	}

	// Add client secret for the client ID for HMAC based signature.
	r.pubKeys.add(pCfg.ClientID, []byte(pCfg.ClientSecret))

	client := &http.Client{
		Transport: r.transport,
	}

	resp, err := client.Get(pCfg.JWKS.URL.String())
	if err != nil {
		return err
	}
	defer r.closeRespFn(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return errors.New(resp.Status)
	}

	return r.pubKeys.parseAndAdd(resp.Body)
}

// ErrTokenExpired - error token expired
var (
	ErrTokenExpired = errors.New("token expired")
)

func updateClaimsExpiry(dsecs string, claims map[string]any) error {
	expStr := claims["exp"]
	if expStr == "" {
		return ErrTokenExpired
	}

	// No custom duration requested, the claims can be used as is.
	if dsecs == "" {
		return nil
	}

	if _, err := auth.ExpToInt64(expStr); err != nil {
		return err
	}

	defaultExpiryDuration, err := GetDefaultExpiration(dsecs)
	if err != nil {
		return err
	}

	claims["exp"] = time.Now().UTC().Add(defaultExpiryDuration).Unix() // update with new expiry.
	return nil
}

const (
	audClaim = "aud"
	azpClaim = "azp"
)

// providerAllowsHMAC reports whether symmetric (HMAC, i.e. HS256/384/512)
// id_token signing is permitted for the given provider.
//
// CVE-2026-33322 / GHSA-5cx5-wh4m-82fh: HMAC verification uses the ClientSecret
// as the key. Permitting HMAC unconditionally enables a JWT algorithm-confusion
// attack against the (overwhelmingly common) asymmetric deployments, where an
// attacker who knows the ClientSecret can forge tokens. We therefore only allow
// HMAC when the IdP's discovery document explicitly advertises an HMAC
// id_token signing algorithm. If the discovery document does not list any
// signing algorithms (HMAC nor asymmetric) we conservatively withhold HMAC,
// since the secure default for OIDC is asymmetric signing.
func providerAllowsHMAC(pCfg *providerCfg) bool {
	for _, alg := range pCfg.DiscoveryDoc.IDTokenSigningAlgValuesSupported {
		switch alg {
		case "HS256", "HS384", "HS512":
			return true
		}
	}
	return false
}

// Validate - validates the id_token.
func (r *Config) Validate(ctx context.Context, arn arn.ARN, token, accessToken, dsecs string, claims map[string]any) error {
	pCfg, ok := r.arnProviderCfgsMap[arn]
	if !ok {
		return fmt.Errorf("Role %s does not exist", arn)
	}

	// CVE-2026-33322 / GHSA-5cx5-wh4m-82fh (JWT algorithm confusion):
	//
	// MinIO registers the OIDC ClientSecret as an HMAC verification key keyed
	// by ClientID (see PopulatePublicKey) so that IdPs which sign id_tokens
	// symmetrically (HS256/384/512) can be supported. However, the verification
	// key is resolved purely from the attacker-controlled `kid` header and the
	// accepted algorithms permitted every family unconditionally. An attacker
	// who learns the ClientSecret could therefore forge a token of the shape
	// {"alg":"HS256","kid":"<ClientID>"}, sign it with the ClientSecret, and
	// have it verified against that same secret - even when the IdP actually
	// signs tokens asymmetrically (RSA/ECDSA). golang-jwt only enforces
	// ValidMethods, not a binding between the algorithm and the key type, so it
	// does not stop this on its own.
	//
	// Mitigation: HMAC (symmetric) signing is only honored when the IdP's
	// discovery document advertises an HMAC id_token signing algorithm. For the
	// common asymmetric deployments the HS* algorithms are removed from the set
	// of accepted methods entirely, which prevents the ClientSecret from ever
	// being used as a token verification key. We additionally bind the token's
	// algorithm to the resolved key's type inside the keyfunc as defense in
	// depth.
	allowHMAC := providerAllowsHMAC(pCfg)

	jp := new(jwtgo.Parser)
	jp.ValidMethods = []string{
		"RS256", "RS384", "RS512",
		"ES256", "ES384", "ES512",
		"RS3256", "RS3384", "RS3512",
		"ES3256", "ES3384", "ES3512",
	}
	if allowHMAC {
		jp.ValidMethods = append(jp.ValidMethods, "HS256", "HS384", "HS512")
	}

	keyFuncCallback := func(jwtToken *jwtgo.Token) (any, error) {
		kid, ok := jwtToken.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("Invalid kid value %v", jwtToken.Header["kid"])
		}
		pubkey := r.pubKeys.get(kid)
		if pubkey == nil {
			return nil, fmt.Errorf("No public key found for kid %s", kid)
		}

		// CVE-2026-33322 / GHSA-5cx5-wh4m-82fh: bind the token's signing
		// algorithm to the TYPE of the resolved verification key so that an
		// asymmetric public key can never be (mis)used as an HMAC secret and a
		// symmetric secret can never be used to satisfy an asymmetric token.
		_, isHMACToken := jwtToken.Method.(*jwtgo.SigningMethodHMAC)
		switch pubkey.(type) {
		case []byte:
			// Symmetric (HMAC) secret. Only acceptable when the token uses an
			// HMAC algorithm AND the provider is configured to permit HMAC.
			if !isHMACToken {
				return nil, fmt.Errorf("signing method %q is not allowed for symmetric (HMAC) key kid %s", jwtToken.Method.Alg(), kid)
			}
			if !allowHMAC {
				return nil, fmt.Errorf("HMAC signing is not permitted for provider with client ID %s; the IdP does not advertise an HMAC id_token signing algorithm", pCfg.ClientID)
			}
		default:
			// Asymmetric public key (RSA/ECDSA/...): HMAC signing methods must
			// never be accepted, otherwise the public key would be treated as
			// an HMAC secret.
			if isHMACToken {
				return nil, fmt.Errorf("HMAC signing method %q is not allowed for asymmetric key kid %s", jwtToken.Method.Alg(), kid)
			}
		}

		return pubkey, nil
	}

	mclaims := jwtgo.MapClaims(claims)
	jwtToken, err := jp.ParseWithClaims(token, &mclaims, keyFuncCallback)
	if err != nil {
		// Re-populate the public key in-case the JWKS
		// pubkeys are refreshed
		if err = r.PopulatePublicKey(arn); err != nil {
			return err
		}
		jwtToken, err = jwtgo.ParseWithClaims(token, &mclaims, keyFuncCallback)
		if err != nil {
			return err
		}
	}

	if !jwtToken.Valid {
		return ErrTokenExpired
	}

	if err = updateClaimsExpiry(dsecs, mclaims); err != nil {
		return err
	}

	if err = r.updateUserinfoClaims(ctx, arn, accessToken, mclaims); err != nil {
		return err
	}

	// Validate that matching clientID appears in the aud or azp claims.

	// REQUIRED. Audience(s) that this ID Token is intended for.
	// It MUST contain the OAuth 2.0 client_id of the Relying Party
	// as an audience value. It MAY also contain identifiers for
	// other audiences. In the general case, the aud value is an
	// array of case sensitive strings. In the common special case
	// when there is one audience, the aud value MAY be a single
	// case sensitive
	audValues, ok := policy.GetValuesFromClaims(mclaims, audClaim)
	if !ok {
		return errors.New("STS JWT Token has `aud` claim invalid, `aud` must match configured OpenID Client ID")
	}
	if !audValues.Contains(pCfg.ClientID) {
		// if audience claims is missing, look for "azp" claims.
		// OPTIONAL. Authorized party - the party to which the ID
		// Token was issued. If present, it MUST contain the OAuth
		// 2.0 Client ID of this party. This Claim is only needed
		// when the ID Token has a single audience value and that
		// audience is different than the authorized party. It MAY
		// be included even when the authorized party is the same
		// as the sole audience. The azp value is a case sensitive
		// string containing a StringOrURI value
		azpValues, ok := policy.GetValuesFromClaims(mclaims, azpClaim)
		if !ok {
			return errors.New("STS JWT Token has `azp` claim invalid, `azp` must match configured OpenID Client ID")
		}
		if !azpValues.Contains(pCfg.ClientID) {
			return errors.New("STS JWT Token has `azp` claim invalid, `azp` must match configured OpenID Client ID")
		}
	}

	return nil
}

func (r *Config) updateUserinfoClaims(ctx context.Context, arn arn.ARN, accessToken string, claims map[string]any) error {
	pCfg, ok := r.arnProviderCfgsMap[arn]
	// If claim user info is enabled, get claims from userInfo
	// and overwrite them with the claims from JWT.
	if ok && pCfg.ClaimUserinfo {
		if accessToken == "" {
			return errors.New("access_token is mandatory if user_info claim is enabled")
		}
		uclaims, err := pCfg.UserInfo(ctx, accessToken, r.transport)
		if err != nil {
			return err
		}
		for k, v := range uclaims {
			if _, ok := claims[k]; !ok { // only add to claims not update it.
				claims[k] = v
			}
		}
	}
	return nil
}

// DiscoveryDoc - parses the output from openid-configuration
// for example https://accounts.google.com/.well-known/openid-configuration
type DiscoveryDoc struct {
	Issuer                           string   `json:"issuer,omitempty"`
	AuthEndpoint                     string   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                    string   `json:"token_endpoint,omitempty"`
	EndSessionEndpoint               string   `json:"end_session_endpoint,omitempty"`
	UserInfoEndpoint                 string   `json:"userinfo_endpoint,omitempty"`
	RevocationEndpoint               string   `json:"revocation_endpoint,omitempty"`
	JwksURI                          string   `json:"jwks_uri,omitempty"`
	ResponseTypesSupported           []string `json:"response_types_supported,omitempty"`
	SubjectTypesSupported            []string `json:"subject_types_supported,omitempty"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported,omitempty"`
	ScopesSupported                  []string `json:"scopes_supported,omitempty"`
	TokenEndpointAuthMethods         []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	ClaimsSupported                  []string `json:"claims_supported,omitempty"`
	CodeChallengeMethodsSupported    []string `json:"code_challenge_methods_supported,omitempty"`
}

func parseDiscoveryDoc(u *xnet.URL, transport http.RoundTripper, closeRespFn func(io.ReadCloser)) (DiscoveryDoc, error) {
	d := DiscoveryDoc{}
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return d, err
	}
	clnt := http.Client{
		Transport: transport,
	}
	resp, err := clnt.Do(req)
	if err != nil {
		return d, err
	}
	defer closeRespFn(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return d, fmt.Errorf("unexpected error returned by %s : status(%s)", u, resp.Status)
	}
	dec := json.NewDecoder(resp.Body)
	if err = dec.Decode(&d); err != nil {
		return d, err
	}
	return d, nil
}
