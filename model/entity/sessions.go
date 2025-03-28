package entity

import (
	"time"

	"github.com/google/uuid"
)

type Session struct {
	ID           uuid.UUID  `db:"id"`
	UserID       int        `db:"user_id"`
	RefreshToken string     `db:"refresh_token"`
	TokenFamily  uuid.UUID  `db:"token_family"`
	ExpiresAt    time.Time  `db:"expires_at"`
	CreatedAt    time.Time  `db:"created_at"`
	RevokedAt    *time.Time `db:"revoked_at"`
}

type SessionWithUser struct {
	ID           uuid.UUID  `db:"id"`
	UserID       int        `db:"user_id"`
	Role         string     `db:"role"`
	RefreshToken string     `db:"refresh_token"`
	TokenFamily  uuid.UUID  `db:"token_family"`
	ExpiresAt    time.Time  `db:"expires_at"`
	CreatedAt    time.Time  `db:"created_at"`
	RevokedAt    *time.Time `db:"revoked_at"`
}

func (u SessionWithUser) RoleToEnum() Role {
	if u.Role == "admin" {
		return ADMIN
	}
	return USER
}
