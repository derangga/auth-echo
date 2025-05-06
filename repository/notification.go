package repository

import (
	"auth-echo/model/entity"
	"context"

	"github.com/jmoiron/sqlx"
)

type notificationRepository struct {
	db *sqlx.DB
}

func NewNotificationRepository(db *sqlx.DB) NotificationRepository {
	return notificationRepository{db: db}
}

var (
	insertNotification = `INSERT INTO fcm_device (user_id, title, message) VALUES (:user_id, :title, :message) RETURNING id`
)

func (r notificationRepository) Create(ctx context.Context, notification entity.Notification) error {
	stmt, err := r.db.PrepareNamedContext(ctx, insertNotification)
	if err != nil {
		return err
	}
	defer stmt.Close()

	row := stmt.QueryRowxContext(ctx, notification)
	if err := row.Err(); err != nil {
		return err
	}

	return nil
}
