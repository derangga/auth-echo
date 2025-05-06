package main

import (
	"auth-echo/app/di"
	"auth-echo/lib/rabbitmq"
	"auth-echo/server/config"
	"context"
	"log"
)

func main() {
	ctx := context.Background()
	config := config.BuildConfig()

	rabbitMqConn, rabbitMqCh := rabbitmq.NewRabbitMQClient(config.RabbitMQConfig)
	rabbitWrapperCh := rabbitmq.NewRabbitMQChannel(rabbitMqCh)
	defer rabbitMqConn.Close()
	defer rabbitMqCh.Close()

	httpServer := di.InitHttpServer(ctx, config, rabbitWrapperCh)

	// setup queue
	rabbitWrapperCh.QueueDeclare(rabbitmq.LOG_USER_LOGIN)
	rabbitWrapperCh.QueueDeclare(rabbitmq.NOTIFY_USER_LOGIN)

	err := httpServer.ListenAndServe()
	if err != nil {
		log.Fatal("failed to serve http:", err.Error())
	}
}
