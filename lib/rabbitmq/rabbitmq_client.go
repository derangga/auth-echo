package rabbitmq

import (
	"auth-echo/server/config"
	"fmt"
	"log"

	amqp "github.com/rabbitmq/amqp091-go"
)

var (
	LOG_USER_LOGIN    = "log_user_login"
	NOTIFY_USER_LOGIN = "notify_user_login"
)

func NewRabbitMQClient(config config.RabbitMQConfig) (*amqp.Connection, *amqp.Channel) {
	address := fmt.Sprintf("amqp://%s:%s@%s:%s", config.User, config.Password, config.Host, config.Port)
	conn, err := amqp.Dial(address)
	if err != nil {
		log.Fatalf("failed to connect RabbitMQ: %s", err)
	}

	ch, err := conn.Channel()
	if err != nil {
		conn.Close()
		log.Fatalf("failed to open a channel: %s", err)
	}

	return conn, ch
}
