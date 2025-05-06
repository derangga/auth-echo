package consumerhandler

import (
	"auth-echo/lib/rabbitmq"
	"auth-echo/model/queue"
	"auth-echo/usecase"
	"context"
	"encoding/json"
	"log"
)

func ConsumeAuthLogger(
	ctx context.Context,
	ch rabbitmq.RabbitMQChannel,
	authLoggerUC usecase.AuthLoggerUsecase,
) error {
	topic := rabbitmq.LOG_USER_LOGIN
	_, err := ch.QueueDeclare(topic)
	if err != nil {
		log.Fatalf("Failed to declare queue %s: %v", topic, err)
		return err
	}

	msgs, err := ch.Consume(topic, "", false, false, false, false, nil)
	if err != nil {
		log.Fatalf("Failed to register consumer for %s: %v", topic, err)
		return err
	}

	go func() {
		for {
			select {
			case d, ok := <-msgs:
				if !ok {
					return
				}

				var logDeviceBody queue.LogDeviceLogin
				if err := json.Unmarshal(d.Body, &logDeviceBody); err != nil {
					log.Printf("Failed to parse logDeviceBody: %v", err)
					d.Nack(false, false)
					continue
				}

				// in this case when log failed will force ack
				if err := authLoggerUC.LogLoginDevice(ctx, logDeviceBody); err != nil {
					log.Printf("stack trace insert log device: %v", err)
				}

				d.Ack(false)

			case <-ctx.Done():
				log.Println("Shutting down order consumer")
				return
			}
		}
	}()

	return nil
}
