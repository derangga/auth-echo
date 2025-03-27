package repository

import (
	"auth-echo/model/entity"
	"context"
	"net"

	"github.com/google/uuid"
)

type UserRepository interface {
	Create(ctx context.Context, user *entity.User) error
	GetByID(ctx context.Context, userid int) (entity.User, error)
	GetByUsername(ctx context.Context, username string) (entity.User, error)
}

type SessionRepository interface {
	Create(ctx context.Context, sessions *entity.Session) (*entity.Session, error)
	RotateToken(ctx context.Context, session *entity.Session) (*entity.Session, error)
	InvalidateByTokenFamily(ctx context.Context, tokenFamily uuid.UUID) error
	GetBySessionId(ctx context.Context, sessionId string) (*entity.SessionWithUser, error)
	GetByToken(ctx context.Context, refreshToken string) (*entity.SessionWithUser, error)
}

type LoginDevicesRepository interface {
	Create(ctx context.Context, loginDevice *entity.UserLoginDevice) error
	UpdateLastLogin(ctx context.Context, deviceId, userAgent string, ipAddr net.IP) error
	GetByDeviceId(ctx context.Context, deviceIdentity string) (*entity.UserLoginDevice, error)
}
