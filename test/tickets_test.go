//go:build integration

package test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func idOf(t *testing.T, m map[string]any) string {
	t.Helper()
	id, ok := m["id"].(string)
	if !ok || id == "" {
		t.Fatalf("response has no id: %v", m)
	}
	return id
}

// The headline proof: Tenant A tries to read, update and delete Tenant B's
// data through every endpoint, and every attempt is "not found".
func TestTenantACannotTouchTenantBData(t *testing.T) {
	srv := newTestServer(t)
	a := srv.newTenant(t, "a")
	b := srv.newTenant(t, "b")

	bTicket := idOf(t, srv.mustCall(t, http.StatusCreated, b.Token, "POST", "/tickets",
		map[string]any{"title": "B's secret ticket", "description": "confidential"}))
	srv.mustCall(t, http.StatusCreated, b.Token, "POST", "/tickets/"+bTicket+"/comments",
		map[string]any{"body": "B's secret comment"})

	attacks := []struct {
		name         string
		method, path string
		body         any
	}{
		{"read ticket", "GET", "/tickets/" + bTicket, nil},
		{"update ticket", "PATCH", "/tickets/" + bTicket, map[string]any{"title": "hacked", "status": "closed"}},
		{"delete ticket", "DELETE", "/tickets/" + bTicket, nil},
		{"read comments", "GET", "/tickets/" + bTicket + "/comments", nil},
		{"add comment", "POST", "/tickets/" + bTicket + "/comments", map[string]any{"body": "injected"}},
	}
	for _, at := range attacks {
		t.Run(at.name, func(t *testing.T) {
			code, body := srv.call(t, a.Token, at.method, at.path, at.body)
			if code != http.StatusNotFound {
				t.Fatalf("%s %s as tenant A = %d, want 404; body %v", at.method, at.path, code, body)
			}
		})
	}

	// A's list must not contain B's ticket.
	list := srv.mustCall(t, http.StatusOK, a.Token, "GET", "/tickets", nil)
	if items, _ := list["tickets"].([]any); len(items) != 0 {
		t.Fatalf("tenant A lists %d tickets, want 0: %v", len(items), items)
	}

	// B's data is exactly as B left it (checked as the owner, bypassing RLS).
	var title, status string
	if err := ownerPool.QueryRow(testCtx(t),
		`SELECT title, status FROM tickets WHERE id = $1`, bTicket).Scan(&title, &status); err != nil {
		t.Fatalf("B's ticket is gone or unreadable: %v", err)
	}
	if title != "B's secret ticket" || status != "open" {
		t.Fatalf("B's ticket was modified: title=%q status=%q", title, status)
	}
	var comments int
	if err := ownerPool.QueryRow(testCtx(t),
		`SELECT count(*) FROM comments WHERE ticket_id = $1`, bTicket).Scan(&comments); err != nil || comments != 1 {
		t.Fatalf("B's comments: count=%d err=%v, want exactly 1 (A's injected comment must not exist)", comments, err)
	}

	// And B can still use their own data normally.
	srv.mustCall(t, http.StatusOK, b.Token, "GET", "/tickets/"+bTicket, nil)
}

func TestClientCannotChooseTenant(t *testing.T) {
	srv := newTestServer(t)
	a := srv.newTenant(t, "a")
	b := srv.newTenant(t, "b")

	// Naming another tenant in the body is rejected outright.
	srv.mustCall(t, http.StatusBadRequest, a.Token, "POST", "/tickets",
		map[string]any{"title": "x", "tenant_id": b.TenantID.String()})

	// A normal create lands in the token's tenant.
	id := idOf(t, srv.mustCall(t, http.StatusCreated, a.Token, "POST", "/tickets", map[string]any{"title": "mine"}))
	var owner string
	if err := ownerPool.QueryRow(testCtx(t), `SELECT tenant_id::text FROM tickets WHERE id = $1`, id).Scan(&owner); err != nil {
		t.Fatalf("query: %v", err)
	}
	if owner != a.TenantID.String() {
		t.Fatalf("ticket belongs to tenant %s, want %s", owner, a.TenantID)
	}
}

func TestEveryTicketRouteRequiresAuthentication(t *testing.T) {
	srv := newTestServer(t)
	a := srv.newTenant(t, "a")
	id := idOf(t, srv.mustCall(t, http.StatusCreated, a.Token, "POST", "/tickets", map[string]any{"title": "t"}))

	routes := []struct{ method, path string }{
		{"POST", "/tickets"}, {"GET", "/tickets"},
		{"GET", "/tickets/" + id}, {"PATCH", "/tickets/" + id}, {"DELETE", "/tickets/" + id},
		{"POST", "/tickets/" + id + "/comments"}, {"GET", "/tickets/" + id + "/comments"},
	}
	for _, r := range routes {
		for name, token := range map[string]string{"no token": "", "tampered token": a.Token + "x"} {
			if code, _ := srv.call(t, token, r.method, r.path, map[string]any{}); code != http.StatusUnauthorized {
				t.Errorf("%s %s with %s = %d, want 401", r.method, r.path, name, code)
			}
		}
	}
}

// Defense in depth behind RLS: the database itself refuses a comment whose
// tenant differs from its ticket's tenant. Tested as the owner, who bypasses
// RLS, to prove the constraint works on its own.
func TestCommentCannotCrossTenantsEvenWithoutRLS(t *testing.T) {
	srv := newTestServer(t)
	a := srv.newTenant(t, "a")
	b := srv.newTenant(t, "b")
	bTicket := idOf(t, srv.mustCall(t, http.StatusCreated, b.Token, "POST", "/tickets", map[string]any{"title": "b"}))

	_, err := ownerPool.Exec(testCtx(t),
		`INSERT INTO comments (tenant_id, ticket_id, author_id, body) VALUES ($1, $2, $3, 'x')`,
		a.TenantID, bTicket, a.UserID)
	var pgErr *pgconn.PgError
	if err == nil || !asPgError(err, &pgErr) || pgErr.Code != "23503" {
		t.Fatalf("cross-tenant comment insert error = %v, want SQLSTATE 23503 (foreign key violation)", err)
	}
}

func TestTicketLifecycleAndPagination(t *testing.T) {
	srv := newTestServer(t)
	a := srv.newTenant(t, "a")

	var ids []string
	for i := 1; i <= 5; i++ {
		ids = append(ids, idOf(t, srv.mustCall(t, http.StatusCreated, a.Token, "POST", "/tickets",
			map[string]any{"title": fmt.Sprintf("ticket %d", i), "description": "keep me", "priority": "low"})))
	}

	// Page through newest-first, two at a time: every ticket exactly once.
	var seen []string
	cursor := ""
	for page := 0; page < 10; page++ {
		path := "/tickets?limit=2"
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		res := srv.mustCall(t, http.StatusOK, a.Token, "GET", path, nil)
		items, _ := res["tickets"].([]any)
		for _, it := range items {
			seen = append(seen, it.(map[string]any)["id"].(string))
		}
		next, _ := res["next_cursor"].(string)
		if next == "" {
			break
		}
		cursor = next
	}
	if len(seen) != 5 {
		t.Fatalf("pagination returned %d tickets, want 5: %v", len(seen), seen)
	}
	for i, id := range seen { // newest first = reverse creation order
		if want := ids[len(ids)-1-i]; id != want {
			t.Fatalf("position %d = %s, want %s (newest first, no duplicates)", i, id, want)
		}
	}

	// Partial update changes only the given field.
	updated := srv.mustCall(t, http.StatusOK, a.Token, "PATCH", "/tickets/"+ids[0], map[string]any{"status": "resolved"})
	if updated["status"] != "resolved" || updated["description"] != "keep me" || updated["title"] != "ticket 1" {
		t.Fatalf("partial update changed other fields: %v", updated)
	}

	// Status filter.
	res := srv.mustCall(t, http.StatusOK, a.Token, "GET", "/tickets?status=resolved", nil)
	if items, _ := res["tickets"].([]any); len(items) != 1 {
		t.Fatalf("status filter returned %d tickets, want 1", len(items))
	}

	// Comments, then delete cascades to them.
	srv.mustCall(t, http.StatusCreated, a.Token, "POST", "/tickets/"+ids[0]+"/comments", map[string]any{"body": "first"})
	srv.mustCall(t, http.StatusCreated, a.Token, "POST", "/tickets/"+ids[0]+"/comments", map[string]any{"body": "second"})
	cs := srv.mustCall(t, http.StatusOK, a.Token, "GET", "/tickets/"+ids[0]+"/comments", nil)
	if items, _ := cs["comments"].([]any); len(items) != 2 || items[0].(map[string]any)["body"] != "first" {
		t.Fatalf("comments = %v, want [first second]", items)
	}

	srv.mustCall(t, http.StatusNoContent, a.Token, "DELETE", "/tickets/"+ids[0], nil)
	srv.mustCall(t, http.StatusNotFound, a.Token, "GET", "/tickets/"+ids[0], nil)
	var left int
	if err := ownerPool.QueryRow(testCtx(t), `SELECT count(*) FROM comments WHERE ticket_id = $1`, ids[0]).Scan(&left); err != nil || left != 0 {
		t.Fatalf("comments left after ticket delete: %d (err %v), want 0", left, err)
	}
}
