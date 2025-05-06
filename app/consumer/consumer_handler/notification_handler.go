package consumerhandler

import (
	"auth-echo/lib/rabbitmq"
	"auth-echo/model/queue"
	"auth-echo/usecase"
	"context"
	"encoding/json"
	"log"
)

func ConsumeNotifyUserLogin(
	ctx context.Context,
	ch rabbitmq.RabbitMQChannel,
	notificationUC usecase.NotificationUsecase,
) error {
	topic := rabbitmq.NOTIFY_USER_LOGIN
	_, err := ch.QueueDeclare(topic)
	if err != nil {
		log.Fatalf("Failed to declare queue %s: %v", topic, err)
		return err
	}

	msgs, err := ch.Consume(topic, "", false, false, false, false, nil)
	if err != nil {
		log.Fatalf("failed to register consumer for %s: %v", topic, err)
		return err
	}

	go func() {
		for {
			select {
			case d, ok := <-msgs:
				if !ok {
					log.Println("notify channel closed")
					return
				}

				var notify queue.NotifyUserOtherDevice
				if err := json.Unmarshal(d.Body, &notify); err != nil {
					log.Printf("failed to parse logDeviceBody: %v", err)
					d.Nack(false, false)
					continue
				}

				// in this case when log failed will force ack
				if err := notificationUC.NotifyNewDeviceLogin(ctx, notify); err != nil {
					log.Printf("failed to notify device login: %v", err)
				}

				d.Ack(false)

			case <-ctx.Done():
				log.Println("shutting down order consumer")
				return
			}
		}
	}()

	return nil
}
