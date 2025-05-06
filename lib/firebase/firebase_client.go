package firebase

import (
	"auth-echo/helper"
	"context"
	"encoding/base64"

	fbClient "firebase.google.com/go/v4"
	"google.golang.org/api/option"
)

func NewFirebaseClient(ctx context.Context) (*fbClient.App, error) {
	fireBaseAuthKey := helper.GetStringEnv("FIREBASE_AUTH_KEY", "")

	decodedKey, err := base64.StdEncoding.DecodeString(fireBaseAuthKey)
	if err != nil {
		return nil, err
	}
	opts := []option.ClientOption{option.WithCredentialsJSON(decodedKey)}

	return fbClient.NewApp(ctx, nil, opts...)
}
