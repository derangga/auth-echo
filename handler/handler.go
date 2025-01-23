package handler

type Handlers struct {
	AuthHandler AuthHandler
	HealthzHandler HealthzHandler
}

func NewHandlers(authHandler AuthHandler, healthzHandler HealthzHandler) Handlers {
	return Handlers{
		AuthHandler: authHandler,
		HealthzHandler: healthzHandler,
	}
}
