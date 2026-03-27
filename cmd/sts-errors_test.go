package cmd

import (
	"context"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSTSLDAPAuthFailureResponse(t *testing.T) {
	w := httptest.NewRecorder()
	writeSTSErrorResponse(context.TODO(), w, ErrSTSLDAPAuthFailure, nil)

	resp := w.Result()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, resp.StatusCode)
	}

	var stsResp STSErrorResponse
	if err := xml.NewDecoder(resp.Body).Decode(&stsResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if stsResp.Error.Code != "AccessDenied" {
		t.Fatalf("expected error code AccessDenied, got %s", stsResp.Error.Code)
	}

	// The message must be generic and must not contain any LDAP-specific
	// details such as DN strings or distinguishable lookup errors.
	if strings.Contains(stsResp.Error.Message, "DN") ||
		strings.Contains(stsResp.Error.Message, "Unable to find") ||
		strings.Contains(stsResp.Error.Message, "auth failed for") {
		t.Fatalf("error message leaks LDAP details: %s", stsResp.Error.Message)
	}
}

func TestSTSTooManyAuthRequestsResponse(t *testing.T) {
	w := httptest.NewRecorder()
	writeSTSErrorResponse(context.TODO(), w, ErrSTSTooManyAuthRequests, nil)

	resp := w.Result()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected status %d, got %d", http.StatusTooManyRequests, resp.StatusCode)
	}

	var stsResp STSErrorResponse
	if err := xml.NewDecoder(resp.Body).Decode(&stsResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if stsResp.Error.Code != "RequestLimitExceeded" {
		t.Fatalf("expected error code RequestLimitExceeded, got %s", stsResp.Error.Code)
	}
}
