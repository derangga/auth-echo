package app_context

import (
	"auth-echo/lib/secret"
	"auth-echo/model/requests"
	"context"
	"errors"
)

type contextKey string

const UserContextKey contextKey = "UserContextKey"
const RefreshTokenContextKey contextKey = "RefreshTokenContextKey"

func GetUserClaims(ctx context.Context) (secret.TokenClaims, error) {
	claims, ok := ctx.Value(UserContextKey).(secret.TokenClaims)
	if !ok {
		return secret.TokenClaims{}, errors.New("failed cast token claims")
	}
	return claims, nil
}

func GetRefreshTokenMeta(ctx context.Context) (requests.RefreshTokenHeaderReq, error) {
	req, ok := ctx.Value(RefreshTokenContextKey).(requests.RefreshTokenHeaderReq)
	if !ok {
		return requests.RefreshTokenHeaderReq{}, errors.New("meta data not found")
	}

	return req, nil
}

func SetUserIDContext(ctx context.Context, id int) context.Context {
	return context.WithValue(ctx, UserContextKey, id)
}

func SetUserClaims(ctx context.Context, claims secret.TokenClaims) context.Context {
	return context.WithValue(ctx, UserContextKey, claims)
}

func SetRefreshTokenRequest(ctx context.Context, rt requests.RefreshTokenHeaderReq) context.Context {
	return context.WithValue(ctx, RefreshTokenContextKey, rt)
}
