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
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/chainguard-forks/minio/internal/auth"
	xhttp "github.com/chainguard-forks/minio/internal/http"
)

// TestSigV4RejectsUnsignedAmzHeaders exercises the three Signature V4
// verification paths (presigned, Authorization header, streaming) against
// requests that carry an x-amz-* header the signature does not cover. Such a
// header must be rejected with ErrUnsignedHeaders regardless of the header,
// because an unsigned x-amz-copy-source is enough to turn a PUT into a
// CopyObject that runs as the signer.
func TestSigV4RejectsUnsignedAmzHeaders(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	obj, fsDir, err := prepareFS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(fsDir)
	if err = newTestConfig(globalMinioDefaultRegion, obj); err != nil {
		t.Fatal(err)
	}

	cred := globalActiveCred
	region := globalSite.Region()
	const targetURL = "http://localhost/dst/target.txt"

	// Headers a holder of a write-only grant could add to steer the request.
	unsignedHeaders := []string{
		xhttp.AmzCopySource,
		xhttp.AmzCopySourceRange,
		xhttp.AmzMetadataDirective,
		xhttp.AmzTagDirective,
		xhttp.AmzObjectTagging,
		"X-Amz-Meta-Injected",
	}

	verify := func(req *http.Request) APIErrorCode {
		if err := req.ParseForm(); err != nil {
			t.Fatal(err)
		}
		return reqSignatureV4Verify(req, region, serviceS3)
	}

	t.Run("presigned", func(t *testing.T) {
		newPresigned := func(t *testing.T) *http.Request {
			req, err := newTestRequest(http.MethodPut, targetURL, 0, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err = preSignV4(req, cred.AccessKey, cred.SecretKey, 60); err != nil {
				t.Fatal(err)
			}
			return req
		}

		// Control: the presigned URL used as intended verifies.
		req := newPresigned(t)
		if code := verify(req); code != ErrNone {
			t.Fatalf("clean presigned request: got %v, want ErrNone", code)
		}
		// The server stamps x-amz-signature-age on success ...
		if req.Header.Get(amzSignatureAge) == "" {
			t.Fatalf("expected %s to be set after verification", amzSignatureAge)
		}
		// ... and a second verification of the same request (PutObject verifies
		// twice) must still pass despite that server-set x-amz-* header.
		if code := verify(req); code != ErrNone {
			t.Fatalf("re-verification of presigned request: got %v, want ErrNone", code)
		}

		for _, header := range unsignedHeaders {
			for _, value := range []string{"/src/secret.txt", ""} {
				req := newPresigned(t)
				req.Header.Set(header, value)
				if code := verify(req); code != ErrUnsignedHeaders {
					t.Errorf("unsigned %s=%q on presigned request: got %v, want ErrUnsignedHeaders", header, value, code)
				}
			}
		}

		// A client-supplied x-amz-signature-age is never trusted: it is dropped
		// before verification and replaced with the server's own value.
		req = newPresigned(t)
		req.Header.Set(amzSignatureAge, "-1")
		if code := verify(req); code != ErrNone {
			t.Fatalf("client-supplied %s should be dropped, got %v", amzSignatureAge, code)
		}
		if got := req.Header.Get(amzSignatureAge); got == "-1" || got == "" {
			t.Fatalf("client-supplied %s was not replaced, got %q", amzSignatureAge, got)
		}

		// An unsigned header that is not x-amz-* is still fine, as before.
		req = newPresigned(t)
		req.Header.Set("User-Agent", "not-signed")
		req.Header.Set("Content-Type", "text/plain")
		if code := verify(req); code != ErrNone {
			t.Fatalf("unsigned non-amz headers on presigned request: got %v, want ErrNone", code)
		}
	})

	t.Run("authorization-header", func(t *testing.T) {
		newSigned := func(t *testing.T, headers map[string]string) *http.Request {
			req, err := newTestSignedRequestV4(http.MethodPut, targetURL, 0, nil, cred.AccessKey, cred.SecretKey, headers)
			if err != nil {
				t.Fatal(err)
			}
			return req
		}

		// Control.
		if code := verify(newSigned(t, nil)); code != ErrNone {
			t.Fatalf("clean signed request: got %v, want ErrNone", code)
		}

		// Each steering header, when part of the signed set, is accepted ...
		for _, header := range unsignedHeaders {
			req := newSigned(t, map[string]string{header: "/src/secret.txt"})
			if code := verify(req); code != ErrNone {
				t.Errorf("signed %s: got %v, want ErrNone", header, code)
			}
			// ... and when added after signing, is rejected.
			req = newSigned(t, nil)
			req.Header.Set(header, "/src/secret.txt")
			if code := verify(req); code != ErrUnsignedHeaders {
				t.Errorf("unsigned %s on signed request: got %v, want ErrUnsignedHeaders", header, code)
			}
		}

		// x-amz-content-sha256 is exempt from the unsigned check because it is
		// the payload hash and already part of the canonical request. Tampering
		// with it therefore fails as a signature mismatch, not as unsigned.
		req := newSigned(t, nil)
		req.Header.Set(xhttp.AmzContentSha256, strings.Repeat("0", 64))
		if code := verify(req); code != ErrSignatureDoesNotMatch && code != ErrContentSHA256Mismatch {
			t.Errorf("tampered %s: got %v, want signature/content mismatch", xhttp.AmzContentSha256, code)
		}

		// A client-supplied x-amz-signature-age is dropped, not rejected, and
		// never survives onto the request for policy evaluation.
		req = newSigned(t, nil)
		req.Header.Set(amzSignatureAge, "1")
		if code := verify(req); code != ErrNone {
			t.Fatalf("client-supplied %s should be dropped, got %v", amzSignatureAge, code)
		}
		if got := req.Header.Get(amzSignatureAge); got != "" {
			t.Fatalf("client-supplied %s survived verification: %q", amzSignatureAge, got)
		}
	})

	t.Run("streaming", func(t *testing.T) {
		newStreaming := func(t *testing.T) *http.Request {
			body := strings.NewReader("data")
			req, err := newTestStreamingSignedRequest(http.MethodPut, targetURL, int64(body.Len()), int64(body.Len()), body, cred.AccessKey, cred.SecretKey)
			if err != nil {
				t.Fatal(err)
			}
			return req
		}

		if _, _, _, _, code := calculateSeedSignature(newStreaming(t), false); code != ErrNone {
			t.Fatalf("clean streaming request: got %v, want ErrNone", code)
		}
		for _, header := range unsignedHeaders {
			req := newStreaming(t)
			req.Header.Set(header, "/src/secret.txt")
			if _, _, _, _, code := calculateSeedSignature(req, false); code != ErrUnsignedHeaders {
				t.Errorf("unsigned %s on streaming request: got %v, want ErrUnsignedHeaders", header, code)
			}
		}
	})
}

// TestAPIUnsignedCopySourceOnPresignedPut is the end-to-end reproduction of
// the reported issue through the real API router: a presigned PUT URL for one
// object, replayed with an unsigned x-amz-copy-source header naming an object
// in another bucket, must not copy that object. It also checks the same on the
// Authorization-header path and that a properly signed CopyObject still works.
func TestAPIUnsignedCopySourceOnPresignedPut(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecExtendedObjectLayerAPITest(t, testAPIUnsignedCopySourceOnPresignedPut, []string{"CopyObject", "PutObject"})
}

func testAPIUnsignedCopySourceOnPresignedPut(obj ObjectLayer, instanceType, bucketName string, apiRouter http.Handler,
	credentials auth.Credentials, t *testing.T,
) {
	ctx := context.Background()
	const targetObject = "target.txt"
	const secretObject = "secret.txt"
	original := []byte("PLACEHOLDER-ORIGINAL-CONTENT\n")
	secret := []byte("THIS-IS-THE-VICTIM-FILE-12345\n")

	// The victim data lives in a second bucket the presigned URL never names.
	srcBucket := getRandomBucketName()
	if err := obj.MakeBucket(ctx, srcBucket, MakeBucketOptions{}); err != nil {
		t.Fatalf("%s: failed to create source bucket: %v", instanceType, err)
	}
	putDirect := func(bucket, object string, data []byte) {
		t.Helper()
		if _, err := obj.PutObject(ctx, bucket, object, mustGetPutObjReader(t, bytes.NewReader(data), int64(len(data)), "", ""), ObjectOptions{}); err != nil {
			t.Fatalf("%s: failed to put %s/%s: %v", instanceType, bucket, object, err)
		}
	}
	readBack := func(bucket, object string) []byte {
		t.Helper()
		r, err := obj.GetObjectNInfo(ctx, bucket, object, nil, nil, ObjectOptions{})
		if err != nil {
			t.Fatalf("%s: failed to read %s/%s: %v", instanceType, bucket, object, err)
		}
		defer r.Close()
		data, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("%s: failed to read %s/%s: %v", instanceType, bucket, object, err)
		}
		return data
	}
	putDirect(srcBucket, secretObject, secret)
	putDirect(bucketName, targetObject, original)

	copySource := "/" + srcBucket + "/" + secretObject
	targetURL := getPutObjectURL("", bucketName, targetObject)

	newPresignedPut := func() *http.Request {
		t.Helper()
		req, err := newTestRequest(http.MethodPut, targetURL, int64(len(original)), bytes.NewReader(original))
		if err != nil {
			t.Fatal(err)
		}
		if err = preSignV4(req, credentials.AccessKey, credentials.SecretKey, 60); err != nil {
			t.Fatal(err)
		}
		return req
	}
	serve := func(req *http.Request) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		apiRouter.ServeHTTP(rec, req)
		return rec
	}
	expectRejected := func(name string, rec *httptest.ResponseRecorder) {
		t.Helper()
		want := getAPIError(ErrUnsignedHeaders)
		if rec.Code != want.HTTPStatusCode {
			t.Errorf("%s: %s: got HTTP %d, want %d; body: %s", instanceType, name, rec.Code, want.HTTPStatusCode, rec.Body)
		}
		var apiErr APIErrorResponse
		if err := xml.Unmarshal(rec.Body.Bytes(), &apiErr); err != nil {
			t.Errorf("%s: %s: failed to decode error response: %v; body: %s", instanceType, name, err, rec.Body)
		} else if apiErr.Code != want.Code {
			t.Errorf("%s: %s: got error code %q, want %q", instanceType, name, apiErr.Code, want.Code)
		}
		// The target must be untouched, and in particular must not now hold the victim.
		if got := readBack(bucketName, targetObject); !bytes.Equal(got, original) {
			t.Errorf("%s: %s: target object was modified: got %q, want %q", instanceType, name, got, original)
		}
	}

	// 1. Control: the presigned URL used as intended is a plain PutObject.
	if rec := serve(newPresignedPut()); rec.Code != http.StatusOK {
		t.Fatalf("%s: control presigned PUT: got HTTP %d, want 200; body: %s", instanceType, rec.Code, rec.Body)
	}
	if got := readBack(bucketName, targetObject); !bytes.Equal(got, original) {
		t.Fatalf("%s: control presigned PUT wrote %q, want %q", instanceType, got, original)
	}

	// 2. The report: the same URL replayed with one unsigned header.
	req := newPresignedPut()
	req.Header.Set(xhttp.AmzCopySource, copySource)
	expectRejected("presigned PUT with unsigned x-amz-copy-source", serve(req))

	// 3. Same thing on the Authorization-header path: sign, then add the header.
	req, err := newTestSignedRequestV4(http.MethodPut, targetURL, int64(len(original)), bytes.NewReader(original),
		credentials.AccessKey, credentials.SecretKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(xhttp.AmzCopySource, copySource)
	expectRejected("signed PUT with unsigned x-amz-copy-source", serve(req))

	// 4. A CopyObject whose x-amz-copy-source is covered by the signature is
	// still allowed, so legitimate copies keep working.
	req, err = newTestSignedRequestV4(http.MethodPut, getCopyObjectURL("", bucketName, targetObject), 0, nil,
		credentials.AccessKey, credentials.SecretKey, map[string]string{xhttp.AmzCopySource: copySource})
	if err != nil {
		t.Fatal(err)
	}
	if rec := serve(req); rec.Code != http.StatusOK {
		t.Fatalf("%s: signed CopyObject: got HTTP %d, want 200; body: %s", instanceType, rec.Code, rec.Body)
	}
	if got := readBack(bucketName, targetObject); !bytes.Equal(got, secret) {
		t.Fatalf("%s: signed CopyObject did not copy: got %q, want %q", instanceType, got, secret)
	}
}

// TestAPIObjectTaggingWithUnsignedHeaderCheck guards the server-side
// X-Amz-Tagging header that PutObjectTagging and DeleteObjectTagging inject so
// that policy conditions can see the tags. That header is set by the server,
// not the client, so it must be added only after the signature has been
// verified, otherwise the unsigned x-amz-* header check rejects the request.
func TestAPIObjectTaggingWithUnsignedHeaderCheck(t *testing.T) {
	defer DetectTestLeak(t)()
	// endpoints nil registers the full API router; the reduced test router does
	// not know the ?tagging routes and would silently send these to PutObject.
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: testAPIObjectTaggingWithUnsignedHeaderCheck, endpoints: nil})
}

func testAPIObjectTaggingWithUnsignedHeaderCheck(obj ObjectLayer, instanceType, bucketName string, apiRouter http.Handler,
	credentials auth.Credentials, t *testing.T,
) {
	const object = "tagged.txt"
	data := []byte("hello")
	if _, err := obj.PutObject(context.Background(), bucketName, object, mustGetPutObjReader(t, bytes.NewReader(data), int64(len(data)), "", ""), ObjectOptions{}); err != nil {
		t.Fatalf("%s: put object: %v", instanceType, err)
	}
	taggingURL := makeTestTargetURL("", bucketName, object, url.Values{"tagging": {""}})
	body := `<Tagging><TagSet><Tag><Key>k</Key><Value>v</Value></Tag></TagSet></Tagging>`
	serve := func(req *http.Request) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		apiRouter.ServeHTTP(rec, req)
		return rec
	}

	// Signed PutObjectTagging.
	req, err := newTestSignedRequestV4(http.MethodPut, taggingURL, int64(len(body)), strings.NewReader(body), credentials.AccessKey, credentials.SecretKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rec := serve(req); rec.Code != http.StatusOK {
		t.Fatalf("%s: signed PutObjectTagging: HTTP %d %s", instanceType, rec.Code, rec.Body)
	}
	// Presigned PutObjectTagging.
	req, err = newTestRequest(http.MethodPut, taggingURL, int64(len(body)), strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if err = preSignV4(req, credentials.AccessKey, credentials.SecretKey, 60); err != nil {
		t.Fatal(err)
	}
	if rec := serve(req); rec.Code != http.StatusOK {
		t.Fatalf("%s: presigned PutObjectTagging: HTTP %d %s", instanceType, rec.Code, rec.Body)
	}
	// GetObjectTagging returns the tag.
	req, err = newTestSignedRequestV4(http.MethodGet, taggingURL, 0, nil, credentials.AccessKey, credentials.SecretKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rec := serve(req); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "<Key>k</Key>") {
		t.Fatalf("%s: GetObjectTagging: HTTP %d %s", instanceType, rec.Code, rec.Body)
	}
	// DeleteObjectTagging on a tagged object is the path that injects X-Amz-Tagging server-side.
	req, err = newTestSignedRequestV4(http.MethodDelete, taggingURL, 0, nil, credentials.AccessKey, credentials.SecretKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rec := serve(req); rec.Code != http.StatusNoContent {
		t.Fatalf("%s: signed DeleteObjectTagging: HTTP %d %s", instanceType, rec.Code, rec.Body)
	}
}
