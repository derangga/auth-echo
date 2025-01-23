package usecase

import (
	"auth-echo/model/dto"
	"auth-echo/model/requests"
	"context"
)

type AuthUsecase interface {
	Register(ctx context.Context, user requests.Register) error
	Login(ctx context.Context, cred requests.Login) (dto.Authorization, error)
	RenewalToken(ctx context.Context, userid int) (dto.Authorization, error)
}