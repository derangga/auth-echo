package middleware

import (
	appctx "auth-echo/lib/app_context"
	"auth-echo/lib/secret"
	"auth-echo/model/requests"
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
)

const (
	AuthorizationHeader = "Authorization"
	AuthorizationPrefix = "Bearer "
)

type JWTAuth struct {
	SigningKey  string
	redisClient *redis.Client
}

func ProvideJWTAuth(secret string, redisClient *redis.Client) *JWTAuth {
	return &JWTAuth{
		SigningKey:  secret,
		redisClient: redisClient,
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

func (m *JWTAuth) UserMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			tokenString, err := m.extractToken(c)
			if err != nil {
				return echo.NewHTTPError(http.StatusUnauthorized, err.Error())
			}

			claims, err := secret.VerifyJWTToken(tokenString, m.SigningKey)
			if err != nil {
				return echo.NewHTTPError(http.StatusUnauthorized, err.Error())
			}

			err = m.isJWTBlocked(c.Request().Context(), claims.ID)
			if err != nil {
				return echo.NewHTTPError(http.StatusUnauthorized, err.Error())
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
			claims, err := secret.VerifyWithoutValidateExp(tokenString, m.SigningKey)
			if err != nil {
				return echo.NewHTTPError(http.StatusUnauthorized, err.Error())
			}

			sessionId, ok := claims["jti"].(string)
			if !ok {
				return echo.NewHTTPError(http.StatusBadRequest, "unknown session")
			}

			// force reject when jwt blocked
			err = m.isJWTBlocked(c.Request().Context(), sessionId)
			if err != nil {
				return echo.NewHTTPError(http.StatusUnauthorized, err.Error())
			}

			exp, err := claims.GetExpirationTime()
			if err != nil {
				return echo.NewHTTPError(http.StatusBadRequest, "failed parse token")
			}
			uid, ok := claims["sub"].(string)
			if !ok {
				return echo.NewHTTPError(http.StatusBadRequest, "unknown session")
			}
			userId, _ := strconv.Atoi(uid)

			deviceId := c.Request().Header.Get("X-Device-ID")
			if deviceId == "" {
				return echo.NewHTTPError(http.StatusBadRequest, "unknown Device Identity")
			}

			req := requests.RefreshTokenHeaderReq{
				SessionId: sessionId,
				UserId:    userId,
				DeviceId:  deviceId,
				ExpiresAt: exp.Time,
			}

			newCtx := appctx.SetRefreshTokenRequest(c.Request().Context(), req)
			c.SetRequest(c.Request().WithContext(newCtx))

			// Call the next handler in the chain
			return next(c)
		}
	}
}

func (m JWTAuth) tokenError(message string) error {
	return errors.New(message)
}

// session id is provided by jti field
func (m JWTAuth) isJWTBlocked(ctx context.Context, sessionId string) error {
	res, err := m.redisClient.Get(ctx, sessionId).Result()
	if err != nil && err != redis.Nil {
		return errors.New("failed validate session")
	}
	if res != "" {
		return errors.New("session expired please re-login")
	}
	return nil
}
