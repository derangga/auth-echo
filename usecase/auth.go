package usecase

import (
	customerror "auth-echo/lib/custom_error"
	"auth-echo/lib/secret"

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

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/gommon/log"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type authUsecase struct {
	config config.AuthConfig
	userRepository repository.UserRepository
}

func NewAuthUsecase(
	config config.AuthConfig,
	userRepository repository.UserRepository,
) AuthUsecase {
	return authUsecase{
		config:	config,
		userRepository: userRepository,
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
	
	err = uc.userRepository.Create(ctx, entity)
	if err != nil {
		log.Errorf("authUsecase Register: %w", err)
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			return uc.errorUnprocessable("username atau email telah terdaftar")
		}
		return err
	}

	return err
}

func (uc authUsecase) Login(ctx context.Context, cred requests.Login) (dto.Authorization, error) {
	user, err := uc.userRepository.GetByUsername(ctx, cred.Username)
	if err != nil {
		log.Errorf("AuthUsecase.getByUsername: %w", err)
		return dto.Authorization{}, uc.errorUnprocessable("")
	}

	if err = uc.validateHash(user.Password, cred.Password); err != nil {
		log.Errorf("AuthUsecase.validateHash: %w", err)
		return dto.Authorization{}, uc.errorUnprocessable("password tidak valid")
	}
	
	accessToken, err := uc.constructJWT(user, secret.AccessToken, uc.config.JWTValidDuration)
	if err != nil {
		log.Errorf("AuthUsecase.constructJWT: %w", err)
		return dto.Authorization{}, uc.errorUnprocessable("")
	}
	refreshToken, err := uc.constructJWT(user, secret.RefreshToken, uc.config.JWTRefreshDuration)
	if err != nil {
		log.Errorf("AuthUsecase.constructRefreshJWT: %w", err)
		return dto.Authorization{}, uc.errorUnprocessable("")
	}
	return dto.Authorization{
		AccessToken: accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (uc authUsecase) RenewalToken(ctx context.Context, userid int) (dto.Authorization, error) {
	user, err := uc.userRepository.GetByID(ctx, userid)
	if err != nil {
		log.Errorf("AuthUsecase.renewalToken: %w", err)
		return dto.Authorization{}, uc.errorUnprocessable("")
	}

	accessToken, err := uc.constructJWT(user, secret.AccessToken, uc.config.JWTValidDuration)
	if err != nil {
		log.Errorf("AuthUsecase.constructJWT: %w", err)
		return dto.Authorization{}, uc.errorUnprocessable("")
	}
	refreshToken, err := uc.constructJWT(user, secret.RefreshToken, uc.config.JWTRefreshDuration)
	if err != nil {
		log.Errorf("AuthUsecase.constructRefreshJWT: %w", err)
		return dto.Authorization{}, uc.errorUnprocessable("")
	}

	return dto.Authorization{
		AccessToken: accessToken,
		RefreshToken: refreshToken,
	}, nil
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

func (uc authUsecase) constructJWT(user entity.User, tokenType string, lifetime time.Duration) (string, error) {
	claims := secret.NewTokenClaims(user.RoleToEnum(), user.ID, tokenType, lifetime)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(uc.config.JWTSecret))
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func (uc authUsecase) errorUnprocessable(message string) error {
	return customerror.BuildError(
		http.StatusUnprocessableEntity, 
		message,
	)
}
