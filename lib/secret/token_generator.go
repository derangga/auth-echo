package secret

import (
	"fmt"
	"time"

	"crypto/rand"
	"encoding/base64"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type JWTPayload struct {
	UserRole  int
	UserID    int
	SessionId string
	DeviceId  string
	Lifetime  time.Duration
}

func ConstructJWT(p JWTPayload, jwtSecret string) (string, error) {
	claims := NewTokenClaims(p.UserRole, p.UserID, p.SessionId, p.DeviceId, p.Lifetime)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func ConstructRefreshToken() (string, error) {
	tokenBytes := make([]byte, 32) // 256-bit token
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}

	// Use URL-safe encoding without padding
	return base64.RawURLEncoding.EncodeToString(tokenBytes), nil
}

func HasedRefreshToken(rawToken string) (string, error) {
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(rawToken), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash token: %w", err)
	}
	return string(hashedBytes), nil
}
