package usecase

import (
	"auth-echo/model/dto"
	"auth-echo/model/requests"
	"context"
)

type AuthUsecase interface {
	Register(ctx context.Context, user requests.Register) error
	Login(ctx context.Context, cred requests.Login, deviceId string) (dto.Authorization, error)
	RenewalToken(ctx context.Context, cred requests.RefreshTokenReq) (dto.Authorization, error)
	Logout(ctx context.Context, deviceId string, userId int) error
}
