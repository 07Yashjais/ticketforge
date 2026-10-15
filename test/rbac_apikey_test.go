//go:build integration

package test

import (
	"net/http"
	"strings"
	"testing"
)

func TestMemberCannotDeleteButAdminCan(t *testing.T) {
	srv := newTestServer(t)
	owner := srv.newTenant(t, "a")
	member := srv.addUser(t, owner, "member")
	admin := srv.addUser(t, owner, "admin")

	id := idOf(t, srv.mustCall(t, http.StatusCreated, member.Token, "POST", "/tickets", map[string]any{"title": "t"}))

	// Members can still do normal work.
	srv.mustCall(t, http.StatusOK, member.Token, "PATCH", "/tickets/"+id, map[string]any{"status": "in_progress"})

	srv.mustCall(t, http.StatusForbidden, member.Token, "DELETE", "/tickets/"+id, nil)
	srv.mustCall(t, http.StatusOK, member.Token, "GET", "/tickets/"+id, nil) // still there

	srv.mustCall(t, http.StatusNoContent, admin.Token, "DELETE", "/tickets/"+id, nil)
	srv.mustCall(t, http.StatusNotFound, owner.Token, "GET", "/tickets/"+id, nil)
}

func TestAPIKeyLifecycle(t *testing.T) {
	srv := newTestServer(t)
	owner := srv.newTenant(t, "a")

	created := srv.mustCall(t, http.StatusCreated, owner.Token, "POST", "/api-keys",
		map[string]any{"name": "CI pipeline", "role": "member"})
	key, _ := created["key"].(string)
	if !strings.HasPrefix(key, "tfk_") {
		t.Fatalf("created key = %q, want tfk_ prefix", key)
	}
	keyID := idOf(t, created)

	// The key works like a member: create and read tickets...
	ticketID := idOf(t, srv.mustCall(t, http.StatusCreated, key, "POST", "/tickets", map[string]any{"title": "from CI"}))
	srv.mustCall(t, http.StatusOK, key, "GET", "/tickets/"+ticketID, nil)
	// ...but not admin things.
	srv.mustCall(t, http.StatusForbidden, key, "DELETE", "/tickets/"+ticketID, nil)
	srv.mustCall(t, http.StatusForbidden, key, "GET", "/api-keys", nil)

	// Listing shows the key's metadata, never the secret or its hash.
	list := srv.mustCall(t, http.StatusOK, owner.Token, "GET", "/api-keys", nil)
	items, _ := list["api_keys"].([]any)
	if len(items) != 1 {
		t.Fatalf("listed %d keys, want 1", len(items))
	}
	k := items[0].(map[string]any)
	if _, hasKey := k["key"]; hasKey {
		t.Fatal("list response contains the secret key")
	}
	if k["last_used_at"] == nil {
		t.Fatal("last_used_at was not recorded after the key was used")
	}

	// The database stores only a hash.
	var stored string
	if err := ownerPool.QueryRow(testCtx(t), `SELECT key_hash FROM api_keys WHERE id = $1`, keyID).Scan(&stored); err != nil {
		t.Fatalf("query: %v", err)
	}
	if stored == key || len(stored) != 64 {
		t.Fatalf("stored value is not a SHA-256 hash: %q", stored)
	}

	// Revoke: the key stops working immediately.
	srv.mustCall(t, http.StatusNoContent, owner.Token, "DELETE", "/api-keys/"+keyID, nil)
	srv.mustCall(t, http.StatusUnauthorized, key, "GET", "/tickets", nil)
	srv.mustCall(t, http.StatusNotFound, owner.Token, "DELETE", "/api-keys/"+keyID, nil) // already revoked
}

func TestAPIKeyRoleRules(t *testing.T) {
	srv := newTestServer(t)
	owner := srv.newTenant(t, "a")
	member := srv.addUser(t, owner, "member")
	admin := srv.addUser(t, owner, "admin")

	srv.mustCall(t, http.StatusForbidden, member.Token, "POST", "/api-keys", map[string]any{"name": "x", "role": "member"})
	srv.mustCall(t, http.StatusBadRequest, owner.Token, "POST", "/api-keys", map[string]any{"name": "x", "role": "owner"})

	// An admin key can delete tickets but still cannot manage keys.
	adminKey := srv.mustCall(t, http.StatusCreated, admin.Token, "POST", "/api-keys",
		map[string]any{"name": "ops", "role": "admin"})["key"].(string)
	id := idOf(t, srv.mustCall(t, http.StatusCreated, adminKey, "POST", "/tickets", map[string]any{"title": "t"}))
	srv.mustCall(t, http.StatusNoContent, adminKey, "DELETE", "/tickets/"+id, nil)
	srv.mustCall(t, http.StatusForbidden, adminKey, "POST", "/api-keys", map[string]any{"name": "y", "role": "member"})
}

func TestAPIKeyIsolatedToItsTenant(t *testing.T) {
	srv := newTestServer(t)
	a := srv.newTenant(t, "a")
	b := srv.newTenant(t, "b")

	aKey := srv.mustCall(t, http.StatusCreated, a.Token, "POST", "/api-keys",
		map[string]any{"name": "a-key", "role": "admin"})["key"].(string)
	bTicket := idOf(t, srv.mustCall(t, http.StatusCreated, b.Token, "POST", "/tickets", map[string]any{"title": "B only"}))
	bKeyID := idOf(t, srv.mustCall(t, http.StatusCreated, b.Token, "POST", "/api-keys",
		map[string]any{"name": "b-key", "role": "member"}))

	// A's key sees nothing of B's.
	srv.mustCall(t, http.StatusNotFound, aKey, "GET", "/tickets/"+bTicket, nil)
	srv.mustCall(t, http.StatusNotFound, aKey, "DELETE", "/tickets/"+bTicket, nil)
	if items, _ := srv.mustCall(t, http.StatusOK, aKey, "GET", "/tickets", nil)["tickets"].([]any); len(items) != 0 {
		t.Fatalf("A's key lists %d tickets, want 0", len(items))
	}

	// A's admin cannot revoke B's key, or even see it.
	srv.mustCall(t, http.StatusNotFound, a.Token, "DELETE", "/api-keys/"+bKeyID, nil)
	if items, _ := srv.mustCall(t, http.StatusOK, a.Token, "GET", "/api-keys", nil)["api_keys"].([]any); len(items) != 1 {
		t.Fatalf("A sees %d keys, want only its own 1", len(items))
	}

	// Forgery: rewrite A's key so its tenant part points at B. It must fail.
	rest := strings.TrimPrefix(aKey, "tfk_")
	_, secret, _ := strings.Cut(rest, "_")
	forged := "tfk_" + strings.ReplaceAll(b.TenantID.String(), "-", "") + "_" + secret
	srv.mustCall(t, http.StatusUnauthorized, forged, "GET", "/tickets", nil)

	// Garbage keys are 401, not 500.
	for _, junk := range []string{"tfk_", "tfk_xyz", "tfk_" + strings.Repeat("0", 32) + "_nope"} {
		srv.mustCall(t, http.StatusUnauthorized, junk, "GET", "/tickets", nil)
	}
}
