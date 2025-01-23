package repository

import (
	"auth-echo/model/entity"
	"context"
)

type UserRepository interface {
	Create(ctx context.Context, user *entity.User) (error)
	GetByID(ctx context.Context, userid int) (entity.User, error)
	GetByUsername(ctx context.Context, username string) (entity.User, error)
}