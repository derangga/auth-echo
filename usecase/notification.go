package usecase

import (
	customerror "auth-echo/lib/custom_error"
	"auth-echo/model/entity"
	"auth-echo/model/queue"
	"auth-echo/model/requests"
	"auth-echo/repository"
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"firebase.google.com/go/v4/messaging"
	"github.com/google/uuid"
	"github.com/labstack/gommon/log"
)

type notificationUsecase struct {
	fcmDeviceRepo    repository.FcmDeviceRepository
	notificationRepo repository.NotificationRepository
	fcm              *messaging.Client
}

func NewNotificationUsecase(
	fcm *messaging.Client,
	fcmDeviceRepo repository.FcmDeviceRepository,
	notificationRepo repository.NotificationRepository,
) NotificationUsecase {
	return notificationUsecase{
		fcm:              fcm,
		fcmDeviceRepo:    fcmDeviceRepo,
		notificationRepo: notificationRepo,
	}
}

func (uc notificationUsecase) RegisterFcmDevice(ctx context.Context, req requests.FcmDevice) error {
	deviceUUID, err := uuid.Parse(req.DeviceIdentity)
	if err != nil {
		log.Errorf("NotificationUsecase.parseUUID: %w", err)
		return uc.errorUnprocessable("failed parse device identity")
	}

	registeredDevice, err := uc.fcmDeviceRepo.GetByUserAndDeviceId(ctx, req.UserID, req.DeviceIdentity)
	if err != nil {
		log.Errorf("NotificationUsecase.getDeviceById: %w", err)
		return uc.errorUnprocessable("")
	}

	if registeredDevice == nil {
		now := time.Now()
		fcmEntity := entity.FcmDevice{
			UserID:         req.UserID,
			DeviceIdentity: deviceUUID,
			FcmToken:       req.Token,
			CreatedAt:      now,
			UpdatedAt:      now,
		}

		err = uc.fcmDeviceRepo.Create(ctx, fcmEntity)
		if err != nil {
			log.Errorf("NotificationUsecase.create: %w", err)
			return uc.errorUnprocessable("failed register device")
		}
	} else {
		err = uc.fcmDeviceRepo.Update(ctx, req.DeviceIdentity, req.Token)
		if err != nil {
			log.Errorf("NotificationUsecase.update: %w", err)
			return uc.errorUnprocessable("failed register device")
		}
	}

	return nil
}

func (uc notificationUsecase) SendNotification(ctx context.Context, notification requests.Notification) error {

	devices, err := uc.fcmDeviceRepo.GetByUserId(ctx, notification.UserID)
	if err != nil {
		log.Errorf("NotificationUsecase.getByUserId: %w", err)
		return err
	}

	tokens := uc.getTokens(devices)
	if len(tokens) == 0 {
		return errors.New("empty firebase token")
	}

	r, err := uc.fcm.SendEachForMulticast(ctx, &messaging.MulticastMessage{
		Notification: &messaging.Notification{
			Title: notification.Title,
			Body:  notification.Message,
		},
		Tokens: tokens,
	})

	if err != nil {
		log.Errorf("NotificationUsecase.sendFcmMulticast: %w", err)
		return err
	}

	log.Info("Response success: ", r.SuccessCount)
	log.Info("Response failed: ", r.FailureCount)

	return nil
}

func (uc notificationUsecase) NotifyNewDeviceLogin(ctx context.Context, queueReq queue.NotifyUserOtherDevice) error {
	devices, err := uc.fcmDeviceRepo.GetByUserIdAndExcludeDeviceId(ctx, queueReq.UserID, queueReq.CurrentDeviceIdentity)
	if err != nil {
		log.Errorf("NotificationUsecase.getByUserIdAndExcludeDeviceId: %w", err)
		return err
	}

	tokens := uc.getTokens(devices)
	if len(tokens) == 0 {
		log.Info("NotificationUsecase: no token firebase registered")
		return nil
	}

	r, err := uc.fcm.SendEachForMulticast(ctx, &messaging.MulticastMessage{
		Notification: &messaging.Notification{
			Title: "New login device detected",
			Body:  fmt.Sprintf("There is a new login device with IP address %s", queueReq.IPAddress),
		},
		Tokens: tokens,
	})

	if err != nil {
		log.Errorf("NotificationUsecase.sendFcmMulticast: %w", err)
		return err
	}

	log.Info("Response success: ", r.SuccessCount)
	log.Info("Response failed: ", r.FailureCount)

	return nil
}

func (uc notificationUsecase) getTokens(devices []entity.FcmDevice) []string {
	tokens := []string{}
	for _, d := range devices {
		tokens = append(tokens, d.FcmToken)
	}

	return tokens
}

func (uc notificationUsecase) errorUnprocessable(message string) error {
	return customerror.BuildError(
		http.StatusUnprocessableEntity,
		message,
	)
}
