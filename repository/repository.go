package repository

import (
	"auth-echo/model/entity"
	"context"

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
	UpdateLastLogin(ctx context.Context, loginDevice entity.UserLoginDevice) error
	GetByDeviceId(ctx context.Context, deviceIdentity string) (*entity.UserLoginDevice, error)
}

type NotificationRepository interface {
	Create(ctx context.Context, notification entity.Notification) error
}

type FcmDeviceRepository interface {
	Create(ctx context.Context, fcmDevice entity.FcmDevice) error
	Update(ctx context.Context, deviceId string, token string) error
	GetByUserAndDeviceId(ctx context.Context, userId int, deviceId string) (*entity.FcmDevice, error)
	GetByUserId(ctx context.Context, userId int) ([]entity.FcmDevice, error)
	GetByUserIdAndExcludeDeviceId(ctx context.Context, userId int, deviceId string) ([]entity.FcmDevice, error)
}
