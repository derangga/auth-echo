package repository

import (
	"auth-echo/model/entity"
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jmoiron/sqlx"
)

type sessionRepository struct {
	db *sqlx.DB
}

func NewSessionRepository(db *sqlx.DB) SessionRepository {
	return sessionRepository{
		db: db,
	}
}

var (
	insertSession = `INSERT INTO sessions(user_id, device_id, refresh_token, expires_at, created_at)
		VALUES (:user_id, :device_id, :refresh_token, :expires_at, :created_at)`
	updateSession        = `UPDATE sessions SET refresh_token=:refresh_token, user_id=:user_id, updated_at=:updated_at, deleted_at=NULL WHERE device_id=:device_id`
	terminateSession     = `UPDATE sessions SET deleted_at=:deleted_at WHERE device_id=:device_id`
	sessionGetByDeviceID = `SELECT user_id, device_id, refresh_token, expires_at FROM sessions WHERE "device_id" = $1 AND "deleted_at" IS NULL`
)

func (r sessionRepository) Create(ctx context.Context, session *entity.Session) error {
	stmt, err := r.db.PrepareNamedContext(ctx, insertSession)
	if err != nil {
		return err
	}

	row := stmt.QueryRowxContext(ctx, session)

	if row.Err() != nil {
		return row.Err()
	}

	defer stmt.Close()

	return nil
}

func (r sessionRepository) GetByDeviceID(ctx context.Context, deviceId string) (*entity.Session, error) {
	var session entity.Session

	err := r.db.GetContext(ctx, &session, sessionGetByDeviceID, deviceId)
	if err != nil {
		return nil, err
	}

	return &session, nil
}

func (r sessionRepository) RenewalSession(ctx context.Context, session *entity.Session) error {
	stmt, err := r.db.PrepareNamedContext(ctx, updateSession)
	defer stmt.Close()

	if err != nil {
		return err
	}

	_, err = stmt.ExecContext(ctx, session)

	return err
}

func (r sessionRepository) TerminateSession(ctx context.Context, userId int, deviceId string) error {
	session, err := r.GetByDeviceID(ctx, deviceId)
	if err != nil {
		return err
	}
	if session.UserID != userId {
		return errors.New("user id is not match")
	}

	stmt, err := r.db.PrepareNamedContext(ctx, terminateSession)
	defer stmt.Close()
	if err != nil {
		return err
	}

	session.DeletedAt = sql.NullTime{
		Time:  time.Now(),
		Valid: true,
	}
	_, err = stmt.ExecContext(ctx, session)

	return err
}
