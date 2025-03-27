package usecase_test

import (
	mock_repository "auth-echo/mocks/repository"
	"auth-echo/model/dto"
	"auth-echo/model/entity"
	"auth-echo/model/requests"
	"auth-echo/server/config"
	"auth-echo/usecase"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

type AuthTestAccessor struct {
	userRepo        *mock_repository.MockUserRepository
	sessionRepo     *mock_repository.MockSessionRepository
	loginDeviceRepo *mock_repository.MockLoginDevicesRepository
	authUC          usecase.AuthUsecase
}

func newAuthTestAccessor(ctrl *gomock.Controller) AuthTestAccessor {
	jwtTime, _ := time.ParseDuration("60s")
	authConfig := config.AuthConfig{
		JWTSecret:        "test",
		JWTValidDuration: jwtTime,
		RefreshDuration:  jwtTime,
		BcryptSalt:       8,
	}
	mockUserRepo := mock_repository.NewMockUserRepository(ctrl)
	mockSessionRepo := mock_repository.NewMockSessionRepository(ctrl)
	mockLoginDeviceRepo := mock_repository.NewMockLoginDevicesRepository(ctrl)
	authUC := usecase.NewAuthUsecase(authConfig, mockUserRepo, mockSessionRepo, mockLoginDeviceRepo)
	return AuthTestAccessor{
		userRepo: mockUserRepo,
		authUC:   authUC,
	}
}

func TestRegister(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	accessor := newAuthTestAccessor(ctrl)
	authUC := accessor.authUC
	ctx := context.Background()

	tests := []struct {
		name      string
		data      requests.Register
		initMock  func()
		assertion func(error)
	}{
		{
			name: "register with invalid email format will return error",
			data: requests.Register{
				Name:     "User Test",
				Username: "usertest",
				Email:    "usertestexample1123.com",
				Password: "apasswordSoL0ng!",
			},
			initMock: func() {},
			assertion: func(err error) {
				assert.Error(t, err)
			},
		},
		{
			name: "register with invalid domain mail format will return error",
			data: requests.Register{
				Name:     "User Test",
				Username: "usertest",
				Email:    "usertestex@ample1123.com",
				Password: "apasswordSoL0ng!",
			},
			initMock: func() {},
			assertion: func(err error) {
				assert.Error(t, err)
			},
		},
		{
			name: "register with small password then return error",
			data: requests.Register{
				Name:     "User Test",
				Username: "usertest",
				Email:    "usertestex@ample1123.com",
				Password: "newpw1",
			},
			initMock: func() {},
			assertion: func(err error) {
				assert.Error(t, err)
			},
		},
		{
			name: "password does not contain small character",
			data: requests.Register{
				Name:     "User Test",
				Username: "usertest",
				Email:    "usertestex@ample1123.com",
				Password: "NEWPW123@@!",
			},
			initMock: func() {},
			assertion: func(err error) {
				assert.Error(t, err)
			},
		},
		{
			name: "password does not contain upper character",
			data: requests.Register{
				Name:     "User Test",
				Username: "usertest",
				Email:    "usertestex@ample1123.com",
				Password: "newpw123@@!",
			},
			initMock: func() {},
			assertion: func(err error) {
				assert.Error(t, err)
			},
		},
		{
			name: "password does not contain special character",
			data: requests.Register{
				Name:     "User Test",
				Username: "usertest",
				Email:    "usertestex@ample1123.com",
				Password: "newpw12344123",
			},
			initMock: func() {},
			assertion: func(err error) {
				assert.Error(t, err)
			},
		},
		{
			name: "password does not contain number character",
			data: requests.Register{
				Name:     "User Test",
				Username: "usertest",
				Email:    "usertestex@ample1123.com",
				Password: "newpw---@@!",
			},
			initMock: func() {},
			assertion: func(err error) {
				assert.Error(t, err)
			},
		},
		{
			name: "register with valid data but sql error constraint",
			data: requests.Register{
				Name:     "User Test",
				Username: "usertest",
				Email:    "usertestex@gmail.com",
				Password: "apasswordSoL0ng!",
			},
			initMock: func() {
				accessor.userRepo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(&pq.Error{
					Code: "23505",
				})
			},
			assertion: func(err error) {
				assert.Error(t, err)
			},
		},
		{
			name: "register with valid data but failed insert",
			data: requests.Register{
				Name:     "User Test",
				Username: "usertest",
				Email:    "usertestex@gmail.com",
				Password: "apasswordSoL0ng!",
			},
			initMock: func() {
				accessor.userRepo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(errors.New("failed insert"))
			},
			assertion: func(err error) {
				assert.Error(t, err)
			},
		},
		{
			name: "register with valid data and success insert",
			data: requests.Register{
				Name:     "User Test",
				Username: "usertest",
				Email:    "usertestex@gmail.com",
				Password: "apasswordSoL0ng!",
			},
			initMock: func() {
				accessor.userRepo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
			},
			assertion: func(err error) {
				assert.NoError(t, err)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.initMock()
			err := authUC.Register(ctx, tt.data)
			tt.assertion(err)
		})
	}
}

func TestLogin(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	accessor := newAuthTestAccessor(ctrl)
	authUC := accessor.authUC
	ctx := context.Background()
	cred := dto.Login{
		Username:       "testusername",
		Password:       "testpassword",
		DeviceIdentity: "abc-123-def",
		IPAddress:      net.IP("127.0.0.1"),
		UserAgent:      "Android",
	}
	mockUser := entity.User{
		ID:        1,
		Username:  "testusername",
		Password:  mockHashPassword("testpassword", 8),
		CreatedAt: time.Now(),
	}
	tests := []struct {
		name       string
		credential dto.Login
		initMock   func()
		assertion  func(dto.Authorization, error)
	}{
		{
			name:       "user login but failed retrieve username then return error",
			credential: cred,
			initMock: func() {
				accessor.userRepo.EXPECT().
					GetByUsername(gomock.Any(), gomock.Any()).Return(entity.User{}, errors.New("failed get user"))
			},
			assertion: func(a dto.Authorization, err error) {
				assert.Error(t, err)
			},
		},
		{
			name:       "user login and invalid password then return error",
			credential: cred,
			initMock: func() {
				user := entity.User{
					ID:        1,
					Username:  "testusername",
					Password:  mockHashPassword("testpassword!", 8),
					CreatedAt: time.Now(),
				}
				accessor.userRepo.EXPECT().
					GetByUsername(gomock.Any(), gomock.Any()).Return(user, nil)
			},
			assertion: func(a dto.Authorization, err error) {
				assert.Error(t, err)
			},
		},
		{
			name:       "user login and success auth then return authorization",
			credential: cred,
			initMock: func() {
				accessor.userRepo.EXPECT().
					GetByUsername(gomock.Any(), gomock.Any()).Return(mockUser, nil)
			},
			assertion: func(a dto.Authorization, err error) {
				assert.NotEmpty(t, a.AccessToken)
				assert.NotEmpty(t, a.RefreshToken)
				assert.NoError(t, err)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.initMock()
			authorization, err := authUC.Login(ctx, tt.credential)
			tt.assertion(authorization, err)
		})
	}

}

func TestRenewalToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	accessor := newAuthTestAccessor(ctrl)
	authUC := accessor.authUC
	ctx := context.Background()

	tests := []struct {
		name      string
		header    requests.RefreshTokenHeaderReq
		body      requests.RefreshTokenBodyReq
		initMock  func()
		assertion func(dto.Authorization, error)
	}{
		{
			name: "user not found when renewal token",
			initMock: func() {
				accessor.userRepo.EXPECT().GetByID(gomock.Any(), gomock.Any()).
					Return(entity.User{}, errors.New("user not found"))
			},
			assertion: func(a dto.Authorization, err error) {
				assert.Error(t, err)
			},
		},
		{
			name: "success renewal token",
			initMock: func() {
				accessor.userRepo.EXPECT().GetByID(gomock.Any(), gomock.Any()).
					Return(entity.User{
						ID:   1,
						Role: "user",
					}, nil)
			},
			assertion: func(a dto.Authorization, err error) {
				assert.NoError(t, err)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.initMock()
			auth, err := authUC.RenewalToken(ctx, tt.header, tt.body)
			tt.assertion(auth, err)
		})
	}
}

func mockHashPassword(password string, salt int) string {
	result, _ := bcrypt.GenerateFromPassword([]byte(password), salt)
	return string(result)
}
