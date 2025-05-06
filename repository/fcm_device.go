package repository

import (
	"auth-echo/model/entity"
	"auth-echo/utils"
	"context"
	"time"

	"github.com/jmoiron/sqlx"
)

type fcmDeviceRepository struct {
	db *sqlx.DB
}

func NewFcmDeviceRepository(db *sqlx.DB) FcmDeviceRepository {
	return fcmDeviceRepository{db: db}
}

func (r fcmDeviceRepository) Create(ctx context.Context, fcmDevice entity.FcmDevice) error {
	query := `INSERT INTO fcm_device (user_id, device_identity, fcm_token, created_at, updated_at) 
		VALUES (:user_id, :device_identity, :fcm_token, :created_at, :updated_at) RETURNING id`
	stmt, err := r.db.PrepareNamedContext(ctx, query)
	if err != nil {
		return err
	}
	defer stmt.Close()

	row := stmt.QueryRowxContext(ctx, fcmDevice)
	if err := row.Err(); err != nil {
		return err
	}

	return nil
}

func (r fcmDeviceRepository) GetByUserAndDeviceId(ctx context.Context, userId int, deviceId string) (*entity.FcmDevice, error) {
	var device entity.FcmDevice
	query := `SELECT id, user_id, device_identity, fcm_token, created_at, updated_at FROM fcm_device 
		WHERE user_id=$1 AND device_identity=$2`
	err := r.db.GetContext(ctx, &device, query, userId, deviceId)
	if err != nil {
		if utils.IsNoRowError(err) {
			return nil, nil
		}

		return nil, err
	}

	return &device, nil
}

func (r fcmDeviceRepository) Update(ctx context.Context, deviceId string, token string) error {
	query := `UPDATE fcm_device SET fcm_token=$2, updated_at=$3 WHERE device_identity=$1`
	_, err := r.db.ExecContext(ctx, query, deviceId, token, time.Now())

	return err
}

func (r fcmDeviceRepository) GetByUserIdAndExcludeDeviceId(ctx context.Context, userId int, deviceId string) ([]entity.FcmDevice, error) {
	var devices []entity.FcmDevice
	query := `SELECT id, user_id, device_identity, fcm_token, created_at, updated_at FROM fcm_device 
		WHERE user_id=$1 AND device_identity!=$2 ORDER BY updated_at DESC LIMIT 3`
	err := r.db.SelectContext(ctx, &devices, query, userId, deviceId)
	if err != nil {
		if utils.IsNoRowError(err) {
			return nil, nil
		}

		return nil, err
	}

	return devices, nil
}

func (r fcmDeviceRepository) GetByUserId(ctx context.Context, userId int) ([]entity.FcmDevice, error) {
	var devices []entity.FcmDevice
	query := `SELECT id, user_id, device_identity, fcm_token, created_at, updated_at FROM fcm_device 
		WHERE user_id=$1 ORDER BY updated_at DESC LIMIT 3`
	err := r.db.SelectContext(ctx, &devices, query, userId)
	if err != nil {
		return nil, err
	}

	return devices, nil
}
