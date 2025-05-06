package rabbitmq

import (
	amqp "github.com/rabbitmq/amqp091-go"
)

type RabbitMQChannel interface {
	Publish(exchange, key string, mandatory, immediate bool, msg amqp.Publishing) error
	Consume(queue, consumer string, autoAck, exclusive, noLocal, noWait bool, args amqp.Table) (<-chan amqp.Delivery, error)
	QueueDeclare(name string) (amqp.Queue, error)
}

type rabbitMQChannel struct {
	Channel *amqp.Channel
}

func NewRabbitMQChannel(channel *amqp.Channel) RabbitMQChannel {
	return rabbitMQChannel{channel}
}

func (rb rabbitMQChannel) Publish(exchange, key string, mandatory, immediate bool, msg amqp.Publishing) error {
	return rb.Channel.Publish(exchange, key, mandatory, immediate, msg)
}

func (rb rabbitMQChannel) Consume(queue, consumer string, autoAck, exclusive, noLocal, noWait bool, args amqp.Table) (<-chan amqp.Delivery, error) {
	return rb.Channel.Consume(queue, consumer, autoAck, exclusive, noLocal, noWait, args)
}

func (rb rabbitMQChannel) QueueDeclare(name string) (amqp.Queue, error) {
	return rb.Channel.QueueDeclare(
		name,
		true,  // durable
		false, // auto-delete when unused
		false, // not exclusive
		false, // no-wait
		nil,   // arguments
	)
}
