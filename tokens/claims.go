package tokens

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AccessClaims is the standard claims for a user access token.
type AccessClaims struct {
	Username string   `json:"usr,omitempty"`
	Groups   []string `json:"grp,omitempty"`
	Orgs     []string `json:"org,omitempty"`
	jwt.RegisteredClaims
}

// RefreshClaims is the standard claims for a user refresh token.
type RefreshClaims struct {
	Namespace string `json:"namespace,omitempty"`
	Username  string `json:"username,omitempty"`
	jwt.RegisteredClaims
}

// newAccessClaims creates a standard claim for a user access token.
func newAccessClaims(username string, groups, orgs []string, expiry time.Time) AccessClaims {
	return AccessClaims{
		username,
		groups,
		orgs,
		jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(expiry)},
	}
}

// newRefreshClaims creates a standard claim for a user refresh token.
func newRefreshClaims(namespace, user string, expiry time.Time) RefreshClaims {
	return RefreshClaims{
		namespace,
		user,
		jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(expiry)},
	}
}
