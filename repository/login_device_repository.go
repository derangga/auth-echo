package repository

import (
	"auth-echo/model/entity"
	"auth-echo/utils"
	"context"
	"time"

	"github.com/jmoiron/sqlx"
)

type loginDeviceRepository struct {
	db *sqlx.DB
}

func NewLoginDeviceRepository(db *sqlx.DB) LoginDevicesRepository {
	return loginDeviceRepository{
		db: db,
	}
}

var (
	insertLoginDevices = `INSERT INTO user_login_devices(user_id, session_id, device_identity, ip_address, user_agent, last_login_at)
    	VALUES (:user_id, :session_id, :device_identity, :ip_address, :user_agent, :last_login_at) RETURNING id`
	updateLastLogin = `UPDATE user_login_devices SET session_id=$2, ip_address=$3, user_agent=$4, last_login_at=$5 WHERE device_identity=$1`
	getByDeviceId   = `SELECT id, user_id, device_identity, ip_address, user_agent, created_at, last_login_at 
		FROM user_login_devices WHERE device_identity=$1 ORDER BY created_at DESC LIMIT 1`
)

func (r loginDeviceRepository) Create(ctx context.Context, loginDevice *entity.UserLoginDevice) error {
	stmt, err := r.db.PrepareNamedContext(ctx, insertLoginDevices)
	if err != nil {
		return err
	}

	row := stmt.QueryRowxContext(ctx, loginDevice)
	if row.Err() != nil {
		return row.Err()
	}

	return nil
}

func (r loginDeviceRepository) GetByDeviceId(ctx context.Context, deviceIdentity string) (*entity.UserLoginDevice, error) {
	var loginDevice entity.UserLoginDevice

	err := r.db.GetContext(ctx, &loginDevice, getByDeviceId, deviceIdentity)
	if err != nil {
		if utils.IsNoRowError(err) {
			return nil, nil
		}

		return nil, err
	}

	return &loginDevice, nil
}

func (r loginDeviceRepository) UpdateLastLogin(ctx context.Context, loginDevice entity.UserLoginDevice) error {
	lastLoginTime := time.Now()
	_, err := r.db.ExecContext(
		ctx,
		updateLastLogin,
		loginDevice.DeviceIdentity,
		loginDevice.SessionId,
		loginDevice.IPAddress,
		loginDevice.UserAgent,
		lastLoginTime,
	)
	if err != nil {
		return err
	}

	return nil
}
