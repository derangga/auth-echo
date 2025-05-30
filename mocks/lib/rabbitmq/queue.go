// Code generated by MockGen. DO NOT EDIT.
// Source: lib/rabbitmq/queue.go

// Package mock_rabbitmq is a generated GoMock package.
package mock_rabbitmq

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	amqp091 "github.com/rabbitmq/amqp091-go"
)

// MockRabbitMQChannel is a mock of RabbitMQChannel interface.
type MockRabbitMQChannel struct {
	ctrl     *gomock.Controller
	recorder *MockRabbitMQChannelMockRecorder
}

// MockRabbitMQChannelMockRecorder is the mock recorder for MockRabbitMQChannel.
type MockRabbitMQChannelMockRecorder struct {
	mock *MockRabbitMQChannel
}

// NewMockRabbitMQChannel creates a new mock instance.
func NewMockRabbitMQChannel(ctrl *gomock.Controller) *MockRabbitMQChannel {
	mock := &MockRabbitMQChannel{ctrl: ctrl}
	mock.recorder = &MockRabbitMQChannelMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockRabbitMQChannel) EXPECT() *MockRabbitMQChannelMockRecorder {
	return m.recorder
}

// Consume mocks base method.
func (m *MockRabbitMQChannel) Consume(queue, consumer string, autoAck, exclusive, noLocal, noWait bool, args amqp091.Table) (<-chan amqp091.Delivery, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Consume", queue, consumer, autoAck, exclusive, noLocal, noWait, args)
	ret0, _ := ret[0].(<-chan amqp091.Delivery)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Consume indicates an expected call of Consume.
func (mr *MockRabbitMQChannelMockRecorder) Consume(queue, consumer, autoAck, exclusive, noLocal, noWait, args interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Consume", reflect.TypeOf((*MockRabbitMQChannel)(nil).Consume), queue, consumer, autoAck, exclusive, noLocal, noWait, args)
}

// Publish mocks base method.
func (m *MockRabbitMQChannel) Publish(exchange, key string, mandatory, immediate bool, msg amqp091.Publishing) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Publish", exchange, key, mandatory, immediate, msg)
	ret0, _ := ret[0].(error)
	return ret0
}

// Publish indicates an expected call of Publish.
func (mr *MockRabbitMQChannelMockRecorder) Publish(exchange, key, mandatory, immediate, msg interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Publish", reflect.TypeOf((*MockRabbitMQChannel)(nil).Publish), exchange, key, mandatory, immediate, msg)
}

// QueueDeclare mocks base method.
func (m *MockRabbitMQChannel) QueueDeclare(name string) (amqp091.Queue, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "QueueDeclare", name)
	ret0, _ := ret[0].(amqp091.Queue)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// QueueDeclare indicates an expected call of QueueDeclare.
func (mr *MockRabbitMQChannelMockRecorder) QueueDeclare(name interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "QueueDeclare", reflect.TypeOf((*MockRabbitMQChannel)(nil).QueueDeclare), name)
}
