package app_context

import (
	"auth-echo/lib/secret"
	"context"
	"errors"
)

type contextKey string

const UserContextKey contextKey = "UserContextKey"

func GetUserClaims(ctx context.Context) (secret.TokenClaims, error) {
	claims, ok := ctx.Value(UserContextKey).(secret.TokenClaims)
	if !ok {
		return secret.TokenClaims{}, errors.New("failed cast token claims")
	}
	return claims, nil
}

func SetUserIDContext(ctx context.Context, id int) context.Context {
	return context.WithValue(ctx, UserContextKey, id)
}

func SetUserClaims(ctx context.Context, claims secret.TokenClaims) context.Context {
	return context.WithValue(ctx, UserContextKey, claims)
}