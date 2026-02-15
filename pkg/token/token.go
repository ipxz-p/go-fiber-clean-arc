package token

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	UserID   int64  `json:"user_id"`
	Email    string `json:"email"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

type JWTManager struct {
	accessSecret        []byte
	refreshSecret       []byte
	accessExpiryMinutes int
	refreshExpiryDays   int
}

func NewJWTManager(accessSecret, refreshSecret string, accessExpiryMinutes, refreshExpiryDays int) *JWTManager {
	return &JWTManager{
		accessSecret:        []byte(accessSecret),
		refreshSecret:       []byte(refreshSecret),
		accessExpiryMinutes: accessExpiryMinutes,
		refreshExpiryDays:   refreshExpiryDays,
	}
}

func (m *JWTManager) GenerateAccessToken(userID int64, email, username string) (string, time.Time, error) {
	expiresAt := time.Now().Add(time.Duration(m.accessExpiryMinutes) * time.Minute)

	claims := &Claims{
		UserID:   userID,
		Email:    email,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   fmt.Sprintf("%d", userID),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(m.accessSecret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to sign access token: %w", err)
	}

	return tokenString, expiresAt, nil
}

func (m *JWTManager) GenerateRefreshToken(userID int64, email, username string) (string, string, time.Time, error) {
	expiresAt := time.Now().Add(time.Duration(m.refreshExpiryDays) * 24 * time.Hour)
	jti := uuid.New().String()

	claims := &Claims{
		UserID:   userID,
		Email:    email,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   fmt.Sprintf("%d", userID),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(m.refreshSecret)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("failed to sign refresh token: %w", err)
	}

	return tokenString, jti, expiresAt, nil
}

func (m *JWTManager) ValidateAccessToken(tokenString string) (*Claims, error) {
	return m.parseToken(tokenString, m.accessSecret)
}

func (m *JWTManager) ValidateRefreshToken(tokenString string) (*Claims, error) {
	return m.parseToken(tokenString, m.refreshSecret)
}

func (m *JWTManager) parseToken(tokenString string, secret []byte) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secret, nil
	})
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}

func (m *JWTManager) RefreshExpiryDuration() time.Duration {
	return time.Duration(m.refreshExpiryDays) * 24 * time.Hour
}
