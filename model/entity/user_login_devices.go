package entity

import (
	"net"
	"time"

	"github.com/google/uuid"
)

type UserLoginDevice struct {
	ID             int       `db:"id"`
	UserID         int       `db:"user_id"`
	SessionId      uuid.UUID `db:"session_id"`
	DeviceIdentity string    `db:"device_identity"`
	IPAddress      net.IP    `db:"ip_address"`
	UserAgent      string    `db:"user_agent"`
	CreatedAt      time.Time `db:"created_at"`
	LastLoginAt    time.Time `db:"last_login_at"`
}
