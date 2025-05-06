package main

import (
	consumerhandler "auth-echo/app/consumer/consumer_handler"
	"auth-echo/app/di"
	"auth-echo/lib/rabbitmq"
	"auth-echo/server/config"
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
)

var (
	topics = []string{}
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	config := config.BuildConfig()
	rabbitMqConn, rabbitMqCh := rabbitmq.NewRabbitMQClient(config.RabbitMQConfig)
	rabbitWrapperCh := rabbitmq.NewRabbitMQChannel(rabbitMqCh)
	defer rabbitMqConn.Close()
	defer rabbitMqCh.Close()

	consumerUC := di.InitConsumer(ctx, config)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		log.Println("Interrupt received, shutting down...")
		cancel()
	}()

	log.Println("consumer started...")
	consumerhandler.ConsumeAuthLogger(ctx, rabbitWrapperCh, consumerUC.AuthLoggerUC)
	consumerhandler.ConsumeNotifyUserLogin(ctx, rabbitWrapperCh, consumerUC.NotificationUC)

	<-ctx.Done()
	log.Println("consumer exited")
}
