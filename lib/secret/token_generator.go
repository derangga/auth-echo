package secret

import (
	"errors"
	"fmt"
	"time"

	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"

	"github.com/golang-jwt/jwt/v5"
)

type JWTPayload struct {
	UserRole int
	UserID   int
	DeviceId string
	Lifetime time.Duration
}

func ConstructJWT(p JWTPayload, jwtSecret string) (string, error) {
	claims := NewTokenClaims(p.UserRole, p.UserID, p.DeviceId, p.Lifetime)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func ConstructRefreshToken(secretKey string) (string, error) {
	// construct secure token with 32bytes
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", errors.New("failed generate token")
	}

	secureToken := base64.URLEncoding.EncodeToString(bytes)

	signToken, err := signToken(secureToken, secretKey)
	if err != nil {
		return "", errors.New("failed sign token")
	}

	return signToken, nil
}

// SignToken signs the opaque token using HMAC-SHA256
func signToken(token, secretKey string) (string, error) {
	h := hmac.New(sha256.New, []byte(secretKey))
	_, err := h.Write([]byte(token))
	if err != nil {
		return "", err
	}

	signature := base64.URLEncoding.EncodeToString(h.Sum(nil))
	signToken := fmt.Sprintf("%s.%s", token, signature)

	return signToken, nil
}
