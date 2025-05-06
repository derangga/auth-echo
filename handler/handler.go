package handler

type Handlers struct {
	AuthHandler         AuthHandler
	NotificationHandler NotificationHandler
	HealthzHandler      HealthzHandler
}

func NewHandlers(authHandler AuthHandler, notificationHandler NotificationHandler, healthzHandler HealthzHandler) Handlers {
	return Handlers{
		AuthHandler:         authHandler,
		NotificationHandler: notificationHandler,
		HealthzHandler:      healthzHandler,
	}
}
