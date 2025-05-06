package usecase_test

import (
	mock_rabbitmq "auth-echo/mocks/lib/rabbitmq"
	mock_repository "auth-echo/mocks/repository"
	"auth-echo/model/dto"
	"auth-echo/model/entity"
	"auth-echo/model/requests"
	"auth-echo/server/config"
	"auth-echo/usecase"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-redis/redismock/v9"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

type AuthTestAccessor struct {
	userRepo        *mock_repository.MockUserRepository
	sessionRepo     *mock_repository.MockSessionRepository
	redisClientMock redismock.ClientMock
	rabbitChMock    *mock_rabbitmq.MockRabbitMQChannel
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
	redisClient, mock := redismock.NewClientMock()
	rabbitChMock := mock_rabbitmq.NewMockRabbitMQChannel(ctrl)
	authUC := usecase.NewAuthUsecase(authConfig, redisClient, rabbitChMock, mockUserRepo, mockSessionRepo)
	return AuthTestAccessor{
		userRepo:        mockUserRepo,
		sessionRepo:     mockSessionRepo,
		redisClientMock: mock,
		rabbitChMock:    rabbitChMock,
		authUC:          authUC,
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
		IPAddress:      "127.0.0.1",
		UserAgent:      "Android",
	}
	mockUser := entity.User{
		ID:        1,
		Username:  "testusername",
		Password:  mockHash("testpassword", 8),
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
					Password:  mockHash("testpassword!", 8),
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
			name:       "failed create session then return unprocessible",
			credential: cred,
			initMock: func() {
				accessor.userRepo.EXPECT().GetByUsername(gomock.Any(), gomock.Any()).Return(mockUser, nil)
				accessor.sessionRepo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil, errors.New("failed create session"))
			},
			assertion: func(a dto.Authorization, err error) {
				assert.Error(t, err)
			},
		},
		{
			name:       "failed publish log device event then return unprocessible",
			credential: cred,
			initMock: func() {
				accessor.userRepo.EXPECT().GetByUsername(gomock.Any(), gomock.Any()).Return(mockUser, nil)
				accessor.sessionRepo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(&entity.Session{
					ID:          uuid.New(),
					UserID:      1,
					TokenFamily: uuid.New(),
				}, nil)
				accessor.rabbitChMock.EXPECT().Publish(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(
					errors.New("failed publish"),
				)
			},
			assertion: func(a dto.Authorization, err error) {
				assert.Error(t, err)
			},
		},
		{
			name:       "failed publish notification should return success",
			credential: cred,
			initMock: func() {
				accessor.userRepo.EXPECT().GetByUsername(gomock.Any(), gomock.Any()).Return(mockUser, nil)
				accessor.sessionRepo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(&entity.Session{
					ID:          uuid.New(),
					UserID:      1,
					TokenFamily: uuid.New(),
				}, nil)
				accessor.rabbitChMock.EXPECT().Publish(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				accessor.rabbitChMock.EXPECT().Publish(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(
					errors.New("failed publish"),
				)
			},
			assertion: func(a dto.Authorization, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name:       "user login and success auth then return authorization",
			credential: cred,
			initMock: func() {
				accessor.userRepo.EXPECT().GetByUsername(gomock.Any(), gomock.Any()).Return(mockUser, nil)
				accessor.sessionRepo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(&entity.Session{
					ID:          uuid.New(),
					UserID:      1,
					TokenFamily: uuid.New(),
				}, nil)
				accessor.rabbitChMock.EXPECT().Publish(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				accessor.rabbitChMock.EXPECT().Publish(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
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

	headerReq := requests.RefreshTokenHeaderReq{
		SessionId: "abc-123-def",
		UserId:    1,
		DeviceId:  "wasd",
		ExpiresAt: time.Now().Add(10 * time.Hour),
	}
	bodyReq := requests.RefreshTokenBodyReq{
		RefreshToken: "examplerefreshtoken",
	}

	tests := []struct {
		name      string
		header    requests.RefreshTokenHeaderReq
		body      requests.RefreshTokenBodyReq
		initMock  func()
		assertion func(dto.Authorization, error)
	}{
		{
			name:   "session not found then return error",
			header: headerReq,
			body:   bodyReq,
			initMock: func() {
				accessor.sessionRepo.EXPECT().GetBySessionId(gomock.Any(), gomock.Any()).Return(nil, errors.New("session not found"))
			},
			assertion: func(a dto.Authorization, err error) {
				assert.Error(t, err)
			},
		},
		{
			name:   "user id is not match then return error",
			header: headerReq,
			body:   bodyReq,
			initMock: func() {
				accessor.sessionRepo.EXPECT().GetBySessionId(gomock.Any(), gomock.Any()).Return(&entity.SessionWithUser{
					ID:     uuid.New(),
					UserID: 2,
				}, nil)
			},
			assertion: func(a dto.Authorization, err error) {
				assert.Error(t, err)
			},
		},
		{
			name:   "refresh token is not match",
			header: headerReq,
			body:   bodyReq,
			initMock: func() {
				accessor.sessionRepo.EXPECT().GetBySessionId(gomock.Any(), gomock.Any()).Return(&entity.SessionWithUser{
					ID:           uuid.New(),
					UserID:       1,
					RefreshToken: mockHash("foobar", 8),
				}, nil)
			},
			assertion: func(a dto.Authorization, err error) {
				assert.Error(t, err)
			},
		},
		{
			name:   "rotate token failed then return error",
			header: headerReq,
			body:   bodyReq,
			initMock: func() {
				accessor.sessionRepo.EXPECT().GetBySessionId(gomock.Any(), gomock.Any()).Return(&entity.SessionWithUser{
					ID:           uuid.New(),
					UserID:       1,
					RefreshToken: mockHash(bodyReq.RefreshToken, 8),
				}, nil)
				accessor.sessionRepo.EXPECT().RotateToken(gomock.Any(), gomock.Any()).Return(nil, errors.New(""))
			},
			assertion: func(a dto.Authorization, err error) {
				assert.Error(t, err)
			},
		},
		{
			name:   "success rotate token",
			header: headerReq,
			body:   bodyReq,
			initMock: func() {
				accessor.sessionRepo.EXPECT().GetBySessionId(gomock.Any(), gomock.Any()).Return(&entity.SessionWithUser{
					ID:           uuid.New(),
					UserID:       1,
					RefreshToken: mockHash(bodyReq.RefreshToken, 8),
				}, nil)
				accessor.sessionRepo.EXPECT().RotateToken(gomock.Any(), gomock.Any()).Return(&entity.Session{
					ID: uuid.New(),
				}, nil)
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
			auth, err := authUC.RenewalToken(ctx, tt.header, tt.body)
			tt.assertion(auth, err)
		})
	}
}

func mockHash(password string, salt int) string {
	result, _ := bcrypt.GenerateFromPassword([]byte(password), salt)
	return string(result)
}
