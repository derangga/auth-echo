package entity

import "time"

type Notification struct {
	ID        int       `db:"id"`
	UserID    int       `db:"user_id"`
	Title     string    `db:"title"`
	Message   string    `db:"message"`
	CreatedAt time.Time `db:"created_at"`
}
