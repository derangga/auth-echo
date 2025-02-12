package usecase

import (
	customerror "auth-echo/lib/custom_error"
	"auth-echo/lib/secret"
	"database/sql"

	"auth-echo/model/dto"
	"auth-echo/model/entity"
	"auth-echo/model/requests"
	"auth-echo/repository"
	"auth-echo/server/config"
	"context"
	"net"
	"net/http"
	"net/mail"
	"strings"
	"time"
	"unicode"

	"github.com/labstack/gommon/log"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type authUsecase struct {
	config      config.AuthConfig
	userRepo    repository.UserRepository
	sessionRepo repository.SessionRepository
}

func NewAuthUsecase(
	config config.AuthConfig,
	userRepo repository.UserRepository,
	sessionRepo repository.SessionRepository,
) AuthUsecase {
	return authUsecase{
		config:      config,
		userRepo:    userRepo,
		sessionRepo: sessionRepo,
	}
}

func (uc authUsecase) Register(ctx context.Context, user requests.Register) error {
	if err := uc.validateEmail(user.Email); err != nil {
		return err
	}

	if err := uc.validatePassword(user.Password); err != nil {
		return err
	}

	password, err := uc.generatePasswordHash(user.Password)
	if err != nil {
		return err
	}

	entity := user.ToEntity()
	entity.Password = password
	entity.Role = "user"
	entity.CreatedAt = time.Now()

	err = uc.userRepo.Create(ctx, entity)
	if err != nil {
		log.Errorf("authUsecase Register: %w", err)
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			return uc.errorUnprocessable("username atau email telah terdaftar")
		}
		return err
	}

	return err
}

func (uc authUsecase) Login(ctx context.Context, cred requests.Login, deviceId string) (dto.Authorization, error) {
	user, err := uc.userRepo.GetByUsername(ctx, cred.Username)
	if err != nil {
		log.Errorf("AuthUsecase.getByUsername: %w", err)
		return dto.Authorization{}, uc.errorUnprocessable("")
	}

	if err = uc.validateHash(user.Password, cred.Password); err != nil {
		log.Errorf("AuthUsecase.validateHash: %w", err)
		return dto.Authorization{}, uc.errorUnprocessable("password tidak valid")
	}

	accessToken, err := secret.ConstructJWT(
		secret.JWTPayload{
			UserRole: user.RoleToEnum(),
			DeviceId: deviceId,
			UserID:   user.ID,
			Lifetime: uc.config.JWTValidDuration,
		}, uc.config.JWTSecret,
	)

	if err != nil {
		log.Errorf("AuthUsecase.constructJWT: %w", err)
		return dto.Authorization{}, uc.errorUnprocessable("")
	}
	refreshToken, err := secret.ConstructRefreshToken(uc.config.RefreshTokenSecret)
	if err != nil {
		log.Errorf("AuthUsecase.constructRefreshJWT: %w", err)
		return dto.Authorization{}, uc.errorUnprocessable("")
	}

	session, err := uc.sessionRepo.GetByDeviceID(ctx, deviceId)
	if err != nil && !strings.Contains(err.Error(), "no rows in result set") {
		log.Errorf("AuthUsecase.getSessionByDeviceID: %w", err)
		return dto.Authorization{}, uc.errorUnprocessable("")
	}

	if session == nil {
		// insert new session
		session = &entity.Session{
			UserID:       user.ID,
			RefreshToken: refreshToken,
			DeviceID:     deviceId,
			ExpiresAt:    time.Now().Add(uc.config.RefreshDuration),
			CreatedAt:    time.Now(),
		}
		err := uc.sessionRepo.Create(ctx, session)
		if err != nil {
			log.Errorf("AuthUsecase.insertSession: %w", err)
			return dto.Authorization{}, uc.errorUnprocessable("")
		}
	} else {
		// update session
		err = uc.updateSession(ctx, refreshToken, user.ID, session)
		if err != nil {
			log.Errorf("AuthUsecase.updateSession: %w", err)
			return dto.Authorization{}, uc.errorUnprocessable("")
		}
	}

	return dto.Authorization{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (uc authUsecase) RenewalToken(ctx context.Context, cred requests.RefreshTokenReq) (dto.Authorization, error) {
	isValid := secret.VerifyRefreshToken(cred.RefreshToken, uc.config.RefreshTokenSecret)
	if !isValid {
		log.Error("AuthUsecase.verify: invalid token")
		return dto.Authorization{}, customerror.BuildError(http.StatusUnauthorized, "")
	}

	session, err := uc.sessionRepo.GetByDeviceID(ctx, cred.DeviceId)
	if err != nil {
		log.Errorf("AuthUsecase.renewalToken: %w", err)
		return dto.Authorization{}, err
	}
	if session.UserID != cred.UserId {
		log.Error("AuthUsecase.verify: invalid user")
		return dto.Authorization{}, customerror.BuildError(http.StatusUnauthorized, "")
	}

	user, err := uc.userRepo.GetByID(ctx, cred.UserId)
	if err != nil {
		log.Errorf("AuthUsecase.renewalToken: %w", err)
		return dto.Authorization{}, uc.errorUnprocessable("")
	}

	accessToken, err := secret.ConstructJWT(secret.JWTPayload{
		UserRole: user.RoleToEnum(),
		DeviceId: cred.DeviceId,
		UserID:   cred.UserId,
		Lifetime: uc.config.JWTValidDuration,
	}, uc.config.JWTSecret)
	if err != nil {
		log.Errorf("AuthUsecase.constructJWT: %w", err)
		return dto.Authorization{}, uc.errorUnprocessable("")
	}
	refreshToken, err := secret.ConstructRefreshToken(uc.config.RefreshTokenSecret)
	if err != nil {
		log.Errorf("AuthUsecase.constructRefreshJWT: %w", err)
		return dto.Authorization{}, uc.errorUnprocessable("")
	}

	err = uc.updateSession(ctx, refreshToken, cred.UserId, session)
	if err != nil {
		log.Errorf("AuthUsecase.updateSession: %w", err)
		return dto.Authorization{}, uc.errorUnprocessable("")
	}

	return dto.Authorization{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (uc authUsecase) Logout(ctx context.Context, deviceId string, userId int) error {
	err := uc.sessionRepo.TerminateSession(ctx, userId, deviceId)
	if err != nil {
		log.Errorf("AuthUsecase.updateSession: %w", err)
		return uc.errorUnprocessable("")
	}

	return nil
}

func (uc authUsecase) updateSession(ctx context.Context, refreshToken string, userId int, session *entity.Session) error {
	session.UserID = userId
	session.RefreshToken = refreshToken
	session.UpdatedAt = sql.NullTime{
		Time:  time.Now(),
		Valid: true,
	}
	err := uc.sessionRepo.RenewalSession(ctx, session)
	return err
}

func (uc authUsecase) validateEmail(email string) error {
	_, err := mail.ParseAddress(email)
	if err != nil {
		return uc.errorUnprocessable("invalid email address format")
	}

	parts := strings.Split(email, "@")
	_, err = net.LookupMX(parts[1])

	if err != nil {
		return uc.errorUnprocessable("domain email not found, please use other email")
	}

	return nil
}

func (uc authUsecase) validatePassword(password string) error {
	if passLenght := len(password); passLenght < 8 || passLenght > 100 {
		return uc.errorUnprocessable("minimum password 8 character")
	}

	var isLower, isUpper, isSpecial, isDigit bool

	for _, char := range password {
		if !isLower && unicode.IsLower(char) {
			isLower = true
		}

		if !isUpper && unicode.IsUpper(char) {
			isUpper = true
		}

		if !isDigit && unicode.IsDigit(char) {
			isDigit = true
		}

		if !isSpecial && (unicode.IsSymbol(char) || unicode.IsPunct(char)) {
			isSpecial = true
		}
	}

	isFormatValid := isLower && isUpper && isDigit && isSpecial
	if !isFormatValid {
		return uc.errorUnprocessable("password must contains lowercase, uppercase, digit, and special character")
	}

	return nil
}

// validate password hash
func (uc authUsecase) validateHash(hashed string, plain string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(plain))
	return err
}

// generateHash implements internal.AuthUsecase.
func (uc authUsecase) generatePasswordHash(password string) (string, error) {
	result, err := bcrypt.GenerateFromPassword([]byte(password), uc.config.BcryptSalt)
	if err != nil {
		log.Errorf("AuthUsecase.generatePasswordHash: %w", err)
		return "", uc.errorUnprocessable("")
	}

	return string(result), nil
}

func (uc authUsecase) errorUnprocessable(message string) error {
	return customerror.BuildError(
		http.StatusUnprocessableEntity,
		message,
	)
}
