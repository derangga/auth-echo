package usecase

import (
	"auth-echo/lib/secret"
	"auth-echo/model/dto"
	"auth-echo/model/queue"
	"auth-echo/model/requests"
	"context"
)

type AuthUsecase interface {
	Register(ctx context.Context, user requests.Register) error
	Login(ctx context.Context, cred dto.Login) (dto.Authorization, error)
	RenewalToken(
		ctx context.Context,
		header requests.RefreshTokenHeaderReq,
		body requests.RefreshTokenBodyReq,
	) (dto.Authorization, error)
	Logout(ctx context.Context, cred secret.TokenClaims) error
}

type AuthLoggerUsecase interface {
	LogLoginDevice(ctx context.Context, queueReq queue.LogDeviceLogin) error
}

type NotificationUsecase interface {
	NotifyNewDeviceLogin(ctx context.Context, queueReq queue.NotifyUserOtherDevice) error
	SendNotification(ctx context.Context, notification requests.Notification) error
	RegisterFcmDevice(ctx context.Context, req requests.FcmDevice) error
}
