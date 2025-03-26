package repository

import (
	"auth-echo/model/entity"
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
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
	insertSession = `INSERT INTO user_sessions(user_id, refresh_token, token_family, expires_at)
    	VALUES (:user_id, :refresh_token, :token_family, :expires_at) RETURNING id`
	updateByTokenFamily = `UPDATE user_sessions SET revoked_at=$2 WHERE token_family=$1 AND revoked_at IS NULL`
	getByToken          = `SELECT us.id, us.user_id, u.role, us.refresh_token, us.token_family, us.expires_at, us.expires_at, us.created_at, us.revoked_at  
		FROM user_sessions us
		INNER JOIN users u ON us.user_id = u.id
		WHERE us.refresh_token=$1 AND us.revoked_at IS NULL AND us.expires_at > NOW()`
	getBySessionId = `SELECT us.id, us.user_id, u.role, us.refresh_token, us.token_family, us.expires_at, us.expires_at, us.created_at, us.revoked_at 
		FROM user_sessions us
		INNER JOIN users u ON us.user_id = u.id
		WHERE us.id=$1 AND us.revoked_at is null AND expires_at > NOW();`
)

func (r sessionRepository) Create(ctx context.Context, session *entity.Session) (*entity.Session, error) {
	stmt, err := r.db.PrepareNamedContext(ctx, insertSession)
	if err != nil {
		return nil, err
	}

	row := stmt.QueryRowxContext(ctx, session)
	if row.Err() != nil {
		return nil, row.Err()
	}

	err = row.Scan(&session.ID)
	if err != nil {
		return nil, err
	}

	return session, nil
}

func (r sessionRepository) InvalidateByTokenFamily(ctx context.Context, tokenFamily uuid.UUID) error {
	revokeAt := time.Now()
	_, err := r.db.ExecContext(ctx, updateByTokenFamily, tokenFamily, revokeAt)
	if err != nil {
		return err
	}

	return nil
}

func (r sessionRepository) GetBySessionId(ctx context.Context, sessionId string) (*entity.SessionWithUser, error) {
	var session entity.SessionWithUser

	err := r.db.GetContext(ctx, &session, getBySessionId, sessionId)
	if err != nil {
		fmt.Println(err.Error())
		return nil, err
	}

	return &session, nil
}

func (r sessionRepository) GetByToken(ctx context.Context, refreshToken string) (*entity.SessionWithUser, error) {
	var session entity.SessionWithUser

	err := r.db.GetContext(ctx, &session, getByToken, refreshToken)
	if err != nil {
		return nil, err
	}

	return &session, nil
}
