package server

import (
	"auth-echo/usecase"
)

type Consumer struct {
	AuthLoggerUC   usecase.AuthLoggerUsecase
	NotificationUC usecase.NotificationUsecase
}

func NewConsumer(
	authLoggerUC usecase.AuthLoggerUsecase,
	notificationUC usecase.NotificationUsecase,
) Consumer {
	return Consumer{
		AuthLoggerUC:   authLoggerUC,
		NotificationUC: notificationUC,
	}
}
