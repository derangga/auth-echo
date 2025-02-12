package secret

import (
	"errors"

	"github.com/golang-jwt/jwt/v5"
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

func VerifyRefreshToken(signedToken, secretKey string) bool {
	parts := len(signedToken) - 44 // Signature length in Base64
	if parts <= 0 {
		return false
	}
	token := signedToken[:parts-1]
	expectedSignature, err := signToken(token, secretKey)
	if err != nil  {
		return false
	}

	return signedToken == expectedSignature
}