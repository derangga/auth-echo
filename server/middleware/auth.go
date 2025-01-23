package middleware

import (
	appctx "auth-echo/lib/app_context"
	"auth-echo/lib/secret"
	"errors"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

const (
	AuthorizationHeader = "Authorization"
	AuthorizationPrefix = "Bearer "
)

type JWTAuth struct {
	SigningKey string
}

func ProvideJWTAuth(secret string) *JWTAuth {
	return &JWTAuth{
		SigningKey: secret,
	}
}

func (m *JWTAuth) extractToken(c echo.Context) (string, error) {
	// Get the Authorization header
	authHeader := c.Request().Header.Get(AuthorizationHeader)

	// Check if the Authorization header is present and starts with "Bearer"
	if authHeader == "" || !strings.HasPrefix(authHeader, AuthorizationPrefix) {
		return "", errors.New("unknown authorization")
	}

	// Extract the token from the header
	tokenString := strings.TrimPrefix(authHeader, AuthorizationPrefix)
	return tokenString, nil
}

func (m *JWTAuth) VerifyToken(tokenString string) (*secret.TokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &secret.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Check the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return secret.TokenClaims{}, m.tokenError("invalid token signing method")
		}

		// Return the secret key
		return []byte(m.SigningKey), nil
	})
	
	if err != nil || !token.Valid {
		return nil, m.tokenError("invalid token")
	}

	claims, ok := token.Claims.(*secret.TokenClaims)
	if !ok {
		return nil, m.tokenError("invalid token claims")
	}

	return claims, nil
}

func (m *JWTAuth) UserMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			tokenString, err := m.extractToken(c)
			if err != nil {
				return echo.NewHTTPError(http.StatusUnauthorized, err.Error())
			}

			claims, err := m.VerifyToken(tokenString)
			if err != nil {
				return echo.NewHTTPError(http.StatusUnauthorized, err.Error())
			}
			if claims.GrantType != secret.AccessToken {
				return echo.NewHTTPError(http.StatusUnauthorized, "invalid token")
			}

			newCtx := appctx.SetUserClaims(c.Request().Context(), *claims)
			c.SetRequest(c.Request().WithContext(newCtx))

			// Call the next handler in the chain
			return next(c)
		}
	}
}

func (m *JWTAuth) ReAuthMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			tokenString, err := m.extractToken(c)
			if err != nil {
				return echo.NewHTTPError(http.StatusUnauthorized, err.Error())
			}

			claims, err := m.VerifyToken(tokenString)
			if err != nil {
				return echo.NewHTTPError(http.StatusUnauthorized, err.Error())
			}
			if claims.GrantType != secret.RefreshToken {
				return echo.NewHTTPError(http.StatusUnauthorized, "invalid token")
			}

			newCtx := appctx.SetUserClaims(c.Request().Context(), *claims)
			c.SetRequest(c.Request().WithContext(newCtx))

			// Call the next handler in the chain
			return next(c)
		}
	}
}

func (m JWTAuth) tokenError(message string) error {
	return errors.New(message)
}
