package repository

import (
	"auth-echo/model/entity"
	"context"

	"github.com/jmoiron/sqlx"
)

type userRepository struct {
	db *sqlx.DB
}

func NewUserRepository(db *sqlx.DB) UserRepository {
	return userRepository{
		db: db,
	}
}

var (
	userGetByUsernameQuery = `SELECT id, username, name, email, password FROM users WHERE "username" = $1 AND "deleted_at" IS NULL`
	userGetByEmailQuery    = `SELECT id, username, name, email, password FROM users WHERE "email" = $1 AND "deleted_at" IS NULL`
	userGetByID            = `SELECT id, username, name, email, password FROM users WHERE "id" = $1 AND "deleted_at" IS NULL`
	insertUser             = `INSERT INTO users(username, name, email, role, password, created_at)
		VALUES (:username, :name, :email, :role, :password, :created_at) RETURNING id`
)

func (r userRepository) Create(ctx context.Context, user *entity.User) error {

	stmt, err := r.db.PrepareNamedContext(ctx, insertUser)
	if err != nil {
		return err
	}
	defer stmt.Close()

	row := stmt.QueryRowxContext(ctx, user)

	if row.Err() != nil {
		return row.Err()
	}

	return nil
}

func (r userRepository) GetByID(ctx context.Context, userid int) (entity.User, error) {
	var user entity.User

	err := r.db.GetContext(ctx, &user, userGetByID, userid)
	if err != nil {
		return entity.User{}, err
	}

	return user, nil
}

func (r userRepository) GetByUsername(ctx context.Context, username string) (entity.User, error) {
	var user entity.User

	err := r.db.GetContext(ctx, &user, userGetByUsernameQuery, username)
	if err != nil {
		return entity.User{}, err
	}

	return user, nil
}
