package repository

import (
	"auth-echo/model/entity"
	"auth-echo/utils"
	"context"
	"net"
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
	insertLoginDevices = `INSERT INTO user_login_devices(user_id, device_identity, ip_address, user_agent, last_login_at)
    	VALUES (:user_id, :device_identity, :ip_address, :user_agent, :last_login_at) RETURNING id`
	updateLastLogin = `UPDATE user_login_devices SET ip_address=$2, user_agent=$3, last_login_at=$4 WHERE device_identity=$1`
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

func (r loginDeviceRepository) UpdateLastLogin(ctx context.Context, deviceId, userAgent string, ipAddr net.IP) error {
	lastLoginTime := time.Now()
	_, err := r.db.ExecContext(ctx, updateLastLogin, deviceId, ipAddr, userAgent, lastLoginTime)
	if err != nil {
		return err
	}

	return nil
}
