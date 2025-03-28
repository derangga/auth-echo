package secret

import (
	"errors"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type TokenClaims struct {
	Role     int    `json:"cur"`
	DeviceId string `json:"identity"`
	jwt.RegisteredClaims
}

func NewTokenClaims(
	role int,
	userid int,
	sessionId string,
	deviceId string,
	tokenLifetime time.Duration,
) *TokenClaims {
	now := time.Now()
	return &TokenClaims{
		Role:     role,
		DeviceId: deviceId,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        sessionId,
			Subject:   strconv.Itoa(userid),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(tokenLifetime)),
		},
	}
}

func (t TokenClaims) GetUserID() (int, error) {
	str, err := t.GetSubject()
	if err != nil {
		return 0, errors.New("failed extract metadata")
	}

	userid, _ := strconv.Atoi(str)
	return userid, nil
}
