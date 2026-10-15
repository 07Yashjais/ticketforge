package auth

// Roles a user (or API key) can hold inside a tenant, stored in
// memberships.role. They form a hierarchy: owner > admin > member.
const (
	RoleOwner  = "owner"
	RoleAdmin  = "admin"
	RoleMember = "member"
)

var roleRank = map[string]int{
	RoleMember: 1,
	RoleAdmin:  2,
	RoleOwner:  3,
}

// IsValidRole reports whether role is one of the known roles.
func IsValidRole(role string) bool {
	return roleRank[role] > 0
}

// HasRole reports whether a caller holding `have` may do something that
// requires at least `need`. Unknown roles never pass (fail closed).
func HasRole(have, need string) bool {
	h, n := roleRank[have], roleRank[need]
	return h > 0 && n > 0 && h >= n
}
