package secret

import (
	"errors"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func VerifyJWTToken(tokenString, signingKey string) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Check the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return TokenClaims{}, errors.New("invalid token signing method")
		}

		// Return the secret key
		return []byte(signingKey), nil
	})
	if err != nil || !token.Valid {
		return nil, errors.New("invalid token")
	}

	claims, ok := token.Claims.(*TokenClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	return claims, nil
}

func VerifyWithoutValidateExp(tokenString, signingKey string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Check the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return TokenClaims{}, errors.New("invalid token signing method")
		}

		// Return the secret key
		return []byte(signingKey), nil
	}, jwt.WithoutClaimsValidation())
	if err != nil || !token.Valid {
		return nil, errors.New("masuk kesini")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	return claims, nil
}

func VerifyRefreshToken(storedHash, rawToken string) bool {
	return bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(rawToken)) == nil
}
