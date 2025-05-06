package usecase

import (
	"auth-echo/model/entity"
	"auth-echo/model/queue"
	"auth-echo/repository"
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/gommon/log"
)

type authLoggerUsecase struct {
	loginDeviceRepo repository.LoginDevicesRepository
}

func NewAuthLoggerUsecase(
	loginDeviceRepo repository.LoginDevicesRepository,
) AuthLoggerUsecase {
	return authLoggerUsecase{
		loginDeviceRepo: loginDeviceRepo,
	}
}

func (uc authLoggerUsecase) LogLoginDevice(ctx context.Context, queueReq queue.LogDeviceLogin) error {
	loginDevice, err := uc.loginDeviceRepo.GetByDeviceId(ctx, queueReq.DeviceIdentity)
	if err != nil {
		log.Errorf("AuthLoggerUsecase.getDeviceById: %w", err)
		return err
	}

	sessionUUID, err := uuid.Parse(queueReq.SessionId)
	if err != nil {
		log.Errorf("AuthLoggerUsecase.parseUUID: %w", err)
		return err
	}

	if loginDevice == nil {
		err = uc.loginDeviceRepo.Create(ctx, &entity.UserLoginDevice{
			UserID:         queueReq.UserID,
			SessionId:      sessionUUID,
			DeviceIdentity: queueReq.DeviceIdentity,
			IPAddress:      queueReq.IPAddress,
			UserAgent:      queueReq.UserAgent,
			LastLoginAt:    time.Now(),
		})
	} else {
		loginDevice.SessionId = sessionUUID
		loginDevice.UserAgent = queueReq.UserAgent
		loginDevice.IPAddress = queueReq.IPAddress
		err = uc.loginDeviceRepo.UpdateLastLogin(ctx, *loginDevice)
	}
	if err != nil {
		log.Errorf("AuthUsecase.upsertLoginDevice: %w", err)
		return err
	}

	return nil
}
