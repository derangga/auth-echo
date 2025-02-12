package entity

import (
	"database/sql"
	"time"
)

type Role = int

type User struct {
	ID        int          `db:"id"`
	Username  string       `db:"username"`
	Role      string       `db:"role"`
	Name      string       `db:"name"`
	Email     string       `db:"email"`
	Password  string       `db:"password"`
	CreatedAt time.Time    `db:"created_at"`
	UpdatedAt sql.NullTime `db:"updated_at"`
	DeletedAt sql.NullTime `db:"deleted_at"`
}

const (
	ADMIN = iota + 1
	USER  = iota
)

func (u User) RoleToEnum() Role {
	if u.Role == "admin" {
		return ADMIN
	}
	return USER
}
