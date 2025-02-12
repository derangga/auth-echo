package repository

import (
	"auth-echo/model/entity"
	"context"
)

type UserRepository interface {
	Create(ctx context.Context, user *entity.User) error
	GetByID(ctx context.Context, userid int) (entity.User, error)
	GetByUsername(ctx context.Context, username string) (entity.User, error)
}

type SessionRepository interface {
	Create(ctx context.Context, sessions *entity.Session) error
	GetByDeviceID(ctx context.Context, deviceId string) (*entity.Session, error)
	RenewalSession(ctx context.Context, session *entity.Session) error
	TerminateSession(ctx context.Context, userId int, deviceId string) error
}
