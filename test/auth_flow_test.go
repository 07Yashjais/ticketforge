//go:build integration

package test

import (
	"errors"
	"strings"
	"testing"

	"github.com/07Yashjais/ticketforge/internal/auth"
	"github.com/jackc/pgx/v5/pgconn"
)

func asPgError(err error, target **pgconn.PgError) bool { return errors.As(err, target) }

func TestSignupConflictsAreAtomic(t *testing.T) {
	svc := newAuthService(t)
	a := signupTenant(t, svc, "a")
	ctx := testCtx(t)

	_, err := svc.Signup(ctx, auth.SignupInput{
		CompanyName: "Dup", Subdomain: a.Subdomain, Email: "fresh@" + a.Subdomain + ".test", Password: testPassword,
	})
	if !errors.Is(err, auth.ErrSubdomainTaken) {
		t.Fatalf("duplicate subdomain error = %v, want ErrSubdomainTaken", err)
	}

	// Same email, different case: tenant row is created first, then the user
	// insert fails, so the tenant must be rolled back.
	newSub := "n" + unique(t)
	_, err = svc.Signup(ctx, auth.SignupInput{
		CompanyName: "Dup2", Subdomain: newSub, Email: strings.ToUpper(a.Email), Password: testPassword,
	})
	if !errors.Is(err, auth.ErrEmailTaken) {
		t.Fatalf("duplicate email error = %v, want ErrEmailTaken", err)
	}
	var orphans int
	if err := ownerPool.QueryRow(ctx, `SELECT count(*) FROM tenants WHERE subdomain = $1`, newSub).Scan(&orphans); err != nil {
		t.Fatalf("count: %v", err)
	}
	if orphans != 0 {
		t.Fatalf("failed signup left %d orphan tenant row(s)", orphans)
	}
}

func TestLogin(t *testing.T) {
	svc := newAuthService(t)
	a := signupTenant(t, svc, "a")
	b := signupTenant(t, svc, "b")
	ctx := testCtx(t)

	pair, err := svc.Login(ctx, auth.LoginInput{Subdomain: a.Subdomain, Email: a.Email, Password: testPassword})
	if err != nil || pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Fatalf("valid login: %+v, %v", pair, err)
	}

	for name, in := range map[string]auth.LoginInput{
		"wrong password":         {Subdomain: a.Subdomain, Email: a.Email, Password: "definitely-wrong"},
		"unknown email":          {Subdomain: a.Subdomain, Email: "ghost@" + a.Subdomain + ".test", Password: testPassword},
		"unknown tenant":         {Subdomain: "nope" + unique(t), Email: a.Email, Password: testPassword},
		"A's user at B's tenant": {Subdomain: b.Subdomain, Email: a.Email, Password: testPassword},
	} {
		if _, err := svc.Login(ctx, in); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Errorf("%s: error = %v, want ErrInvalidCredentials", name, err)
		}
	}
}

func TestRefreshRotationAndReuseDetection(t *testing.T) {
	svc := newAuthService(t)
	a := signupTenant(t, svc, "a")
	ctx := testCtx(t)

	first, err := svc.Login(ctx, auth.LoginInput{Subdomain: a.Subdomain, Email: a.Email, Password: testPassword})
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	second, err := svc.Refresh(ctx, first.RefreshToken)
	if err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	if second.RefreshToken == first.RefreshToken {
		t.Fatal("refresh token was not rotated")
	}

	// Replaying the retired token is theft: it must fail AND kill the family.
	if _, err := svc.Refresh(ctx, first.RefreshToken); !errors.Is(err, auth.ErrInvalidRefreshToken) {
		t.Fatalf("replayed token error = %v, want ErrInvalidRefreshToken", err)
	}
	if _, err := svc.Refresh(ctx, second.RefreshToken); !errors.Is(err, auth.ErrInvalidRefreshToken) {
		t.Fatalf("token after reuse detection error = %v, want ErrInvalidRefreshToken (family revoked)", err)
	}
}

func TestRefreshRejectsForeignOrForgedTokens(t *testing.T) {
	svc := newAuthService(t)
	a := signupTenant(t, svc, "a")
	b := signupTenant(t, svc, "b")
	ctx := testCtx(t)

	pair, err := svc.Login(ctx, auth.LoginInput{Subdomain: a.Subdomain, Email: a.Email, Password: testPassword})
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	// A valid token for tenant A with B's tenant ID swapped into the prefix.
	_, secret, _ := strings.Cut(pair.RefreshToken, ".")
	forged := b.TenantID.String() + "." + secret

	for name, tok := range map[string]string{
		"prefix swapped to another tenant": forged,
		"no prefix":                        secret,
		"empty":                            "",
		"garbage":                          "not-a-uuid.xyz",
	} {
		if _, err := svc.Refresh(ctx, tok); !errors.Is(err, auth.ErrInvalidRefreshToken) {
			t.Errorf("%s: error = %v, want ErrInvalidRefreshToken", name, err)
		}
	}

	// The real token must still work: the forgery attempts changed nothing.
	if _, err := svc.Refresh(ctx, pair.RefreshToken); err != nil {
		t.Fatalf("genuine token stopped working after forgery attempts: %v", err)
	}
}
