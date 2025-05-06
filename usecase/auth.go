package usecase

import (
	customerror "auth-echo/lib/custom_error"
	"auth-echo/lib/rabbitmq"
	"auth-echo/lib/secret"
	"auth-echo/utils"
	"encoding/json"

	"auth-echo/model/dto"
	"auth-echo/model/entity"
	"auth-echo/model/queue"
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

	"github.com/google/uuid"
	"github.com/labstack/gommon/log"
	"github.com/lib/pq"
	amqp "github.com/rabbitmq/amqp091-go"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
)

type authUsecase struct {
	config      config.AuthConfig
	redisClient *redis.Client
	rabbitMqCh  rabbitmq.RabbitMQChannel
	userRepo    repository.UserRepository
	sessionRepo repository.SessionRepository
}

func NewAuthUsecase(
	config config.AuthConfig,
	redisClient *redis.Client,
	rabbitMqCh rabbitmq.RabbitMQChannel,
	userRepo repository.UserRepository,
	sessionRepo repository.SessionRepository,
) AuthUsecase {
	return authUsecase{
		config:      config,
		redisClient: redisClient,
		rabbitMqCh:  rabbitMqCh,
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

func (uc authUsecase) Login(ctx context.Context, cred dto.Login) (dto.Authorization, error) {
	user, err := uc.userRepo.GetByUsername(ctx, cred.Username)
	if err != nil {
		if utils.IsNoRowError(err) {
			return dto.Authorization{}, uc.errorUnprocessable("please use correct credential")
		}
		log.Errorf("AuthUsecase.getByUsername: %w", err)
		return dto.Authorization{}, uc.errorUnprocessable("")
	}

	if err = uc.validateHash(user.Password, cred.Password); err != nil {
		log.Errorf("AuthUsecase.validateHash: %w", err)
		return dto.Authorization{}, uc.errorUnprocessable("please use correct credential")
	}

	// create session
	refreshToken, err := uc.generateRefreshToken()
	if err != nil {
		log.Errorf("AuthUsecase.generateRefreshToken: %w", err)
		return dto.Authorization{}, uc.errorUnprocessable("")
	}

	uuid := uuid.New()
	session, err := uc.sessionRepo.Create(ctx, &entity.Session{
		UserID:       user.ID,
		RefreshToken: refreshToken[1],
		TokenFamily:  uuid,
		ExpiresAt:    time.Now().Add(uc.config.RefreshDuration),
	})
	if err != nil {
		log.Errorf("AuthUsecase.createSession: %w", err)
		return dto.Authorization{}, uc.errorUnprocessable("")
	}

	logDevice := queue.LogDeviceLogin{
		UserID:         user.ID,
		DeviceIdentity: cred.DeviceIdentity,
		SessionId:      session.ID.String(),
		IPAddress:      cred.IPAddress,
		UserAgent:      cred.UserAgent,
	}
	logDeviceBody, err := json.Marshal(logDevice)
	if err != nil {
		log.Errorf("AuthUsecase.jsonMarshal: %w", err)
		return dto.Authorization{}, uc.errorUnprocessable("")
	}

	err = uc.rabbitMqCh.Publish("", rabbitmq.LOG_USER_LOGIN, false, false, amqp.Publishing{
		ContentType: "application/json",
		Body:        logDeviceBody,
	})
	if err != nil {
		log.Errorf("AuthUsecase.publish: %w", err)
		return dto.Authorization{}, uc.errorUnprocessable("")
	}

	notifyOtherDevice := queue.NotifyUserOtherDevice{
		UserID:                user.ID,
		CurrentDeviceIdentity: cred.DeviceIdentity,
		IPAddress:             cred.IPAddress,
	}
	notifyOtherDeviceBody, err := json.Marshal(notifyOtherDevice)
	if err != nil {
		log.Errorf("AuthUsecase.jsonMarshal: %w", err)
	}

	err = uc.rabbitMqCh.Publish("", rabbitmq.NOTIFY_USER_LOGIN, false, false, amqp.Publishing{
		ContentType: "application/json",
		Body:        notifyOtherDeviceBody,
	})
	if err != nil {
		log.Errorf("AuthUsecase.publish: %w", err)
	}

	accessToken, err := secret.ConstructJWT(secret.JWTPayload{
		UserID:    user.ID,
		UserRole:  user.RoleToEnum(),
		SessionId: session.ID.String(),
		DeviceId:  cred.DeviceIdentity,
		Lifetime:  uc.config.JWTValidDuration,
	}, uc.config.JWTSecret)

	return dto.Authorization{
		AccessToken:  accessToken,
		RefreshToken: refreshToken[0],
	}, nil
}

func (uc authUsecase) RenewalToken(
	ctx context.Context,
	header requests.RefreshTokenHeaderReq,
	body requests.RefreshTokenBodyReq,
) (dto.Authorization, error) {
	session, err := uc.sessionRepo.GetBySessionId(ctx, header.SessionId)
	if err != nil {
		log.Error("AuthUsecase.failedGetSession: invalid token: %w", err)
		return dto.Authorization{}, customerror.BuildError(http.StatusUnauthorized, "invalid session")
	}

	if header.UserId != session.UserID {
		return dto.Authorization{}, customerror.BuildError(http.StatusUnauthorized, "invalid refresh token")
	}

	if isValid := secret.VerifyRefreshToken(session.RefreshToken, body.RefreshToken); !isValid {
		return dto.Authorization{}, customerror.BuildError(http.StatusUnauthorized, "invalid refresh token")
	}

	// create session
	refreshToken, err := uc.generateRefreshToken()
	if err != nil {
		log.Errorf("AuthUsecase.generateRefreshToken: %w", err)
		return dto.Authorization{}, uc.errorUnprocessable("")
	}

	newSession, err := uc.sessionRepo.RotateToken(ctx, &entity.Session{
		UserID:       session.UserID,
		RefreshToken: refreshToken[1],
		TokenFamily:  session.TokenFamily,
		ExpiresAt:    time.Now().Add(uc.config.RefreshDuration),
	})
	if err != nil {
		log.Errorf("AuthUsecase.rotateToken: %w", err)
		return dto.Authorization{}, uc.errorUnprocessable("")
	}

	// block session id using redis
	// this is to reject the access token request
	now := time.Now()
	if now.Before(header.ExpiresAt) {
		uc.redisClient.SetNX(ctx, header.SessionId, "token rotate", header.ExpiresAt.Sub(now))
	}

	accessToken, err := secret.ConstructJWT(secret.JWTPayload{
		UserID:    header.UserId,
		UserRole:  session.RoleToEnum(),
		SessionId: newSession.ID.String(),
		DeviceId:  header.DeviceId,
		Lifetime:  uc.config.JWTValidDuration,
	}, uc.config.JWTSecret)

	return dto.Authorization{
		AccessToken:  accessToken,
		RefreshToken: refreshToken[0],
	}, nil
}

func (uc authUsecase) Logout(ctx context.Context, cred secret.TokenClaims) error {
	session, err := uc.sessionRepo.GetBySessionId(ctx, cred.ID)
	if err != nil {
		log.Errorf("AuthUsecase.getSessionId: %w", err)
	}
	err = uc.sessionRepo.InvalidateByTokenFamily(ctx, session.TokenFamily)
	if err != nil {
		log.Errorf("AuthUsecase.invalidateToken: %w", err)
		return uc.errorUnprocessable("")
	}

	// block jwt token
	now := time.Now()
	expTime, err := cred.GetExpirationTime()
	if err != nil {
		log.Errorf("AuthUsecase.getExpirationTime: %w", err)
	}
	uc.redisClient.SetNX(ctx, session.ID.String(), "user logout", expTime.Sub(now))

	return nil
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

func (uc authUsecase) generateRefreshToken() ([]string, error) {
	refreshToken, err := secret.ConstructRefreshToken()
	if err != nil {
		return nil, err
	}
	hashedRefreshToken, err := secret.HasedRefreshToken(refreshToken)
	if err != nil {
		return nil, err
	}

	return []string{refreshToken, hashedRefreshToken}, nil
}
