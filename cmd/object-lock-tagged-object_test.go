// Copyright (c) 2015-2026 MinIO, Inc.
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

package cmd

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/chainguard-forks/minio/internal/amztime"
	"github.com/chainguard-forks/minio/internal/auth"
	xhttp "github.com/chainguard-forks/minio/internal/http"
)

// TestObjectLockMetadataOnTaggedObject verifies that a GET/HEAD of an object
// that carries user tags still returns the object lock response headers.
//
// The handlers set X-Amz-Tagging on the *inbound* request so that policy
// conditions can see the tags, and then re-run full request authentication via
// checkRequestAuthType() to compute the GetObjectRetention /
// GetObjectLegalHold permissions used to filter the lock metadata. If SigV4
// verification rejects x-amz-* headers that were not signed, that second
// verification fails on the server-injected header and the lock metadata is
// silently stripped from the response.
func TestObjectLockMetadataOnTaggedObject(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:                 t,
		objAPITest:        testObjectLockMetadataOnTaggedObject,
		endpoints:         nil, // register the full API router
		makeBucketOptions: MakeBucketOptions{LockEnabled: true},
	})
}

// taggingURL returns the ?tagging sub-resource URL for an object.
func taggingURL(endPoint, bucketName, objectName string) string {
	q := url.Values{}
	q.Set("tagging", "")
	return makeTestTargetURL(endPoint, bucketName, objectName, q)
}

func testObjectLockMetadataOnTaggedObject(obj ObjectLayer, instanceType, bucketName string,
	apiRouter http.Handler, creds auth.Credentials, t *testing.T,
) {
	retainUntil := amztime.ISO8601Format(time.Now().UTC().Add(72 * time.Hour))

	// Genuine, client-supplied, *signed* object lock headers on the PUT.
	lockHeaders := map[string]string{
		xhttp.AmzObjectLockMode:            "GOVERNANCE",
		xhttp.AmzObjectLockRetainUntilDate: retainUntil,
		xhttp.AmzObjectLockLegalHold:       "ON",
	}

	putObject := func(t *testing.T, object string) {
		t.Helper()
		payload := []byte("object-lock-payload")
		body := bytes.NewReader(payload)
		req, err := newTestSignedRequestV4(http.MethodPut,
			getPutObjectURL("", bucketName, object),
			int64(len(payload)), body, creds.AccessKey, creds.SecretKey, lockHeaders)
		if err != nil {
			t.Fatalf("%s: failed to build PUT request: %v", instanceType, err)
		}
		rec := httptest.NewRecorder()
		apiRouter.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: PUT %s: got %d, want 200. body=%s", instanceType, object, rec.Code, rec.Body.String())
		}
	}

	putTags := func(t *testing.T, object string) {
		t.Helper()
		taggingXML := []byte(`<Tagging><TagSet><Tag><Key>team</Key><Value>security</Value></Tag></TagSet></Tagging>`)
		body := bytes.NewReader(taggingXML)
		req, err := newTestSignedRequestV4(http.MethodPut,
			taggingURL("", bucketName, object),
			int64(len(taggingXML)), body, creds.AccessKey, creds.SecretKey, nil)
		if err != nil {
			t.Fatalf("%s: failed to build PutObjectTagging request: %v", instanceType, err)
		}
		rec := httptest.NewRecorder()
		apiRouter.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: PutObjectTagging %s: got %d, want 200. body=%s", instanceType, object, rec.Code, rec.Body.String())
		}
	}

	const (
		taggedObject   = "locked-with-tags.txt"
		untaggedObject = "locked-no-tags.txt"
	)

	putObject(t, untaggedObject)
	putObject(t, taggedObject)
	putTags(t, taggedObject)

	// --- Establish what key casing MinIO actually persists ----------------
	for _, object := range []string{untaggedObject, taggedObject} {
		oi, err := obj.GetObjectInfo(t.Context(), bucketName, object, ObjectOptions{})
		if err != nil {
			t.Fatalf("%s: GetObjectInfo(%s): %v", instanceType, object, err)
		}
		keys := make([]string, 0, len(oi.UserDefined))
		for k := range oi.UserDefined {
			if strings.Contains(strings.ToLower(k), "object-lock") {
				keys = append(keys, fmt.Sprintf("%s=%q", k, oi.UserDefined[k]))
			}
		}
		sort.Strings(keys)
		t.Logf("%s: stored object-lock metadata for %s (UserTags=%q): %v",
			instanceType, object, oi.UserTags, keys)
		if len(keys) != 3 {
			t.Fatalf("%s: fixture is wrong: expected 3 object-lock metadata keys on %s, got %v",
				instanceType, object, keys)
		}
	}

	// --- The actual check -------------------------------------------------
	wantHeaders := map[string]string{
		xhttp.AmzObjectLockMode:            "GOVERNANCE",
		xhttp.AmzObjectLockRetainUntilDate: retainUntil,
		xhttp.AmzObjectLockLegalHold:       "ON",
	}

	type reqBuilder func(t *testing.T, method, urlStr string) *http.Request

	signed := func(t *testing.T, method, urlStr string) *http.Request {
		t.Helper()
		req, err := newTestSignedRequestV4(method, urlStr, 0, nil, creds.AccessKey, creds.SecretKey, nil)
		if err != nil {
			t.Fatalf("failed to build signed request: %v", err)
		}
		return req
	}
	signedV2 := func(t *testing.T, method, urlStr string) *http.Request {
		t.Helper()
		req, err := newTestSignedRequestV2(method, urlStr, 0, nil, creds.AccessKey, creds.SecretKey, nil)
		if err != nil {
			t.Fatalf("failed to build SigV2-signed request: %v", err)
		}
		return req
	}
	presigned := func(t *testing.T, method, urlStr string) *http.Request {
		t.Helper()
		req, err := newTestRequest(method, urlStr, 0, nil)
		if err != nil {
			t.Fatalf("failed to build request: %v", err)
		}
		if err := preSignV4(req, creds.AccessKey, creds.SecretKey, 600); err != nil {
			t.Fatalf("failed to presign request: %v", err)
		}
		return req
	}

	cases := []struct {
		name   string
		method string
		object string
		build  reqBuilder
	}{
		{"signed-GET-untagged", http.MethodGet, untaggedObject, signed},
		{"signed-GET-tagged", http.MethodGet, taggedObject, signed},
		{"signed-HEAD-untagged", http.MethodHead, untaggedObject, signed},
		{"signed-HEAD-tagged", http.MethodHead, taggedObject, signed},
		{"presigned-GET-untagged", http.MethodGet, untaggedObject, presigned},
		{"presigned-GET-tagged", http.MethodGet, taggedObject, presigned},
		{"presigned-HEAD-untagged", http.MethodHead, untaggedObject, presigned},
		{"presigned-HEAD-tagged", http.MethodHead, taggedObject, presigned},
		// SigV2 exercises a different re-verification path: the V2 string-to-sign
		// includes every x-amz-* header, so the server-injected X-Amz-Tagging
		// breaks it independently of the SigV4 change under review.
		{"sigv2-GET-untagged", http.MethodGet, untaggedObject, signedV2},
		{"sigv2-GET-tagged", http.MethodGet, taggedObject, signedV2},
		{"sigv2-HEAD-untagged", http.MethodHead, untaggedObject, signedV2},
		{"sigv2-HEAD-tagged", http.MethodHead, taggedObject, signedV2},
	}

	for _, tc := range cases {
		t.Run(instanceType+"/"+tc.name, func(t *testing.T) {
			urlStr := getGetObjectURL("", bucketName, tc.object)
			if tc.method == http.MethodHead {
				urlStr = getHeadObjectURL("", bucketName, tc.object)
			}
			req := tc.build(t, tc.method, urlStr)
			rec := httptest.NewRecorder()
			apiRouter.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s %s: got status %d, want 200. body=%s",
					tc.method, tc.object, rec.Code, rec.Body.String())
			}
			for hdr, want := range wantHeaders {
				if got := rec.Header().Get(hdr); got != want {
					t.Errorf("%s %s (%s): header %s = %q, want %q\nall response headers: %v",
						tc.method, tc.object, tc.name, hdr, got, want, rec.Header())
				}
			}
		})
	}
}

// TestObjectLockMetadataFilteredWhenRetentionDenied is the negative counterpart
// of TestObjectLockMetadataOnTaggedObject: a caller that is allowed
// s3:GetObject but NOT s3:GetObjectRetention / s3:GetObjectLegalHold must still
// have the lock metadata stripped from the GET/HEAD response. It guards against
// a "fix" that simply stops evaluating those two permissions.
func TestObjectLockMetadataFilteredWhenRetentionDenied(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:                 t,
		objAPITest:        testObjectLockMetadataFilteredWhenRetentionDenied,
		endpoints:         nil,
		makeBucketOptions: MakeBucketOptions{LockEnabled: true},
	})
}

func testObjectLockMetadataFilteredWhenRetentionDenied(obj ObjectLayer, instanceType, bucketName string,
	apiRouter http.Handler, creds auth.Credentials, t *testing.T,
) {
	retainUntil := amztime.ISO8601Format(time.Now().UTC().Add(72 * time.Hour))
	lockHeaders := map[string]string{
		xhttp.AmzObjectLockMode:            "GOVERNANCE",
		xhttp.AmzObjectLockRetainUntilDate: retainUntil,
		xhttp.AmzObjectLockLegalHold:       "ON",
	}

	const (
		taggedObject   = "anon-locked-with-tags.txt"
		untaggedObject = "anon-locked-no-tags.txt"
	)

	for _, object := range []string{untaggedObject, taggedObject} {
		payload := []byte("object-lock-payload")
		body := bytes.NewReader(payload)
		req, err := newTestSignedRequestV4(http.MethodPut,
			getPutObjectURL("", bucketName, object),
			int64(len(payload)), body, creds.AccessKey, creds.SecretKey, lockHeaders)
		if err != nil {
			t.Fatalf("%s: failed to build PUT request: %v", instanceType, err)
		}
		rec := httptest.NewRecorder()
		apiRouter.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: PUT %s: got %d, want 200. body=%s", instanceType, object, rec.Code, rec.Body.String())
		}
	}

	taggingXML := []byte(`<Tagging><TagSet><Tag><Key>team</Key><Value>security</Value></Tag></TagSet></Tagging>`)
	req, err := newTestSignedRequestV4(http.MethodPut,
		taggingURL("", bucketName, taggedObject),
		int64(len(taggingXML)), bytes.NewReader(taggingXML), creds.AccessKey, creds.SecretKey, nil)
	if err != nil {
		t.Fatalf("%s: failed to build PutObjectTagging request: %v", instanceType, err)
	}
	rec := httptest.NewRecorder()
	apiRouter.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: PutObjectTagging: got %d, want 200. body=%s", instanceType, rec.Code, rec.Body.String())
	}

	// Anonymous read access only: s3:GetObject, nothing else.
	bucketPolicy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow",`+
		`"Principal":{"AWS":["*"]},"Action":["s3:GetObject"],"Resource":["arn:aws:s3:::%s/*"]}]}`, bucketName)
	req, err = newTestSignedRequestV4(http.MethodPut, getPutPolicyURL("", bucketName),
		int64(len(bucketPolicy)), bytes.NewReader([]byte(bucketPolicy)), creds.AccessKey, creds.SecretKey, nil)
	if err != nil {
		t.Fatalf("%s: failed to build PutBucketPolicy request: %v", instanceType, err)
	}
	rec = httptest.NewRecorder()
	apiRouter.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent && rec.Code != http.StatusOK {
		t.Fatalf("%s: PutBucketPolicy: got %d. body=%s", instanceType, rec.Code, rec.Body.String())
	}

	lockHeaderNames := []string{
		xhttp.AmzObjectLockMode,
		xhttp.AmzObjectLockRetainUntilDate,
		xhttp.AmzObjectLockLegalHold,
	}

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		for _, object := range []string{untaggedObject, taggedObject} {
			name := fmt.Sprintf("%s/anon-%s-%s", instanceType, strings.ToLower(method), object)
			t.Run(name, func(t *testing.T) {
				anonReq, err := newTestRequest(method, getGetObjectURL("", bucketName, object), 0, nil)
				if err != nil {
					t.Fatalf("failed to build anonymous request: %v", err)
				}
				rec := httptest.NewRecorder()
				apiRouter.ServeHTTP(rec, anonReq)
				if rec.Code != http.StatusOK {
					t.Fatalf("%s %s anonymous: got status %d, want 200. body=%s",
						method, object, rec.Code, rec.Body.String())
				}
				for _, hdr := range lockHeaderNames {
					if got := rec.Header().Get(hdr); got != "" {
						t.Errorf("%s %s anonymous (s3:GetObject only): header %s leaked as %q; "+
							"object lock metadata must be filtered\nall response headers: %v",
							method, object, hdr, got, rec.Header())
					}
				}
			})
		}
	}
}
