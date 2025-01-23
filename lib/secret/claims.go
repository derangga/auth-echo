package secret

import (
	"errors"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type TokenClaims struct {
	Role int 			`json:"cur"`
	GrantType string 	`json:"grant_type"`
	jwt.RegisteredClaims 
}

const (
	AccessToken = "access_token"
	RefreshToken = "refresh"
)

func NewTokenClaims(
	role int,
	userid int,
	tokenType string,
	tokenLifetime time.Duration,
) *TokenClaims {
	now := time.Now()
	return &TokenClaims{
			Role: role,
			GrantType: tokenType,
			RegisteredClaims: jwt.RegisteredClaims{
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