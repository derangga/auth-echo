package entity

import (
	"database/sql"
	"time"
)

type Session struct {
	ID           int          `db:"id"`
	UserID       int          `db:"user_id"`
	RefreshToken string       `db:"refresh_token"`
	DeviceID     string       `db:"device_id"`
	ExpiresAt    time.Time    `db:"expires_at"`
	CreatedAt    time.Time    `db:"created_at"`
	UpdatedAt    sql.NullTime `db:"updated_at"`
	DeletedAt    sql.NullTime `db:"deleted_at"`
}
