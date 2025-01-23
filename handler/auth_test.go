package handler_test

import (
	"auth-echo/handler"
	mock_usecase "auth-echo/mocks/usecase"
	"auth-echo/model/dto"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

type AuthHandlerTestAccessor struct {
	authUC		*mock_usecase.MockAuthUsecase
	authHandler handler.AuthHandler
}

func newAuthHandlerTestAccessor(ctrl *gomock.Controller) AuthHandlerTestAccessor {
	authUC := mock_usecase.NewMockAuthUsecase(ctrl)
	validator := validator.New()
	authHandler := handler.NewAuthHandler(authUC, validator)
	return AuthHandlerTestAccessor{
		authUC: authUC,
		authHandler: authHandler,
	}
}

func TestLogin(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	accessor := newAuthHandlerTestAccessor(ctrl)
	h := accessor.authHandler
	e := echo.New()
	body := `{"username":"dummyusername","password":"longpassword123!"}`

	tests := []struct{
		name string
		bodyreq string
		initMock func()
		assertion func(echo.Context, *httptest.ResponseRecorder, error)
	} {
		{
			name: "request login success return 200",
			bodyreq: body,
			initMock: func() {
				accessor.authUC.EXPECT().Login(gomock.Any(), gomock.Any()).Return(dto.Authorization{
					AccessToken: "ascas123",
					RefreshToken: "dasklj123",
				}, nil)
			},
			assertion: func(ctx echo.Context, rec *httptest.ResponseRecorder, err error) {
				assert.NoError(t, err)
				assert.Equal(t, http.StatusOK, rec.Code)
			},
		},
		{
			name: "request login failed return 422",
			bodyreq: body,
			initMock: func() {
				accessor.authUC.EXPECT().Login(gomock.Any(), gomock.Any()).Return(dto.Authorization{}, errors.New("user not found"))
			},
			assertion: func(ctx echo.Context, rec *httptest.ResponseRecorder, err error) {
				assert.NoError(t, err)
				assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
			},
		},
		{
			name: "request login failed return 400",
			bodyreq: `{"username":"dummyusername"`,
			initMock: func() {},
			assertion: func(ctx echo.Context, rec *httptest.ResponseRecorder, err error) {
				assert.NoError(t, err)
				assert.Equal(t, http.StatusBadRequest, rec.Code)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.initMock()
			
			req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(tt.bodyreq))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			err := h.Login(c)
			
			tt.assertion(c, rec, err)
		})
	}
}
