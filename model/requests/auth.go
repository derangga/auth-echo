package requests

import "auth-echo/model/entity"

type Register struct {
	Name     string `json:"name" validate:"required,min=5,max=50"`
	Username string `json:"username" validate:"required,min=6,max=15"`
	Email    string `json:"email" validate:"required,omitempty,email"`
	Password string `json:"password" validate:"required,min=8,max=100"`
}

func (r Register) ToEntity() *entity.User {
	return &entity.User{
		Name:     r.Name,
		Username: r.Username,
		Email:    r.Email,
	}
}

type Login struct {
	Username string `json:"username" validate:"required,min=6,max=15"`
	Password string `json:"password" validate:"required,min=8,max=100"`
}

type RefreshTokenReq struct {
	RefreshToken string
	UserId       int
	DeviceId     string
}
