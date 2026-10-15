package auth

import "testing"

func TestHasRole(t *testing.T) {
	tests := []struct {
		have, need string
		want       bool
	}{
		{RoleOwner, RoleOwner, true},
		{RoleOwner, RoleAdmin, true},
		{RoleOwner, RoleMember, true},
		{RoleAdmin, RoleOwner, false},
		{RoleAdmin, RoleAdmin, true},
		{RoleAdmin, RoleMember, true},
		{RoleMember, RoleAdmin, false},
		{RoleMember, RoleMember, true},
		// Unknown or empty roles fail closed in both directions.
		{"", RoleMember, false},
		{"superadmin", RoleMember, false},
		{RoleOwner, "", false},
		{RoleOwner, "typo", false},
	}
	for _, tt := range tests {
		if got := HasRole(tt.have, tt.need); got != tt.want {
			t.Errorf("HasRole(%q, %q) = %v, want %v", tt.have, tt.need, got, tt.want)
		}
	}
}

func TestIsValidRole(t *testing.T) {
	for _, r := range []string{RoleOwner, RoleAdmin, RoleMember} {
		if !IsValidRole(r) {
			t.Errorf("IsValidRole(%q) = false", r)
		}
	}
	if IsValidRole("root") || IsValidRole("") {
		t.Error("unknown roles must be invalid")
	}
}
