package entity

import (
	"time"

	"github.com/google/uuid"
)

type FcmDevice struct {
	ID             int       `db:"id"`
	UserID         int       `db:"user_id"`
	DeviceIdentity uuid.UUID `db:"device_identity"`
	FcmToken       string    `db:"fcm_token"`
	CreatedAt      time.Time `db:"created_at"`
	UpdatedAt      time.Time `db:"updated_at"`
}
