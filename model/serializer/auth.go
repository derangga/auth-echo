package serializer

import "auth-echo/model/dto"

type AuthResponse struct {
	AccessToken string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

func PublicAuthorization(auth dto.Authorization) AuthResponse {
	return AuthResponse{
		AccessToken: auth.AccessToken,
		RefreshToken: auth.RefreshToken,
	}
}