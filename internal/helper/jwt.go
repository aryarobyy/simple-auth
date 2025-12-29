package helper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"auth/internal/model"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

func ParseExpiry(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("empty expiry string")
	}

	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return 0, err
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}

	return time.ParseDuration(s)
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func refreshKey(jti string) string {
	return "refresh:" + jti
}

func CreateAccessToken(user model.User) (string, error) {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		return "", errors.New("JWT_SECRET missing")
	}

	expiryStr := os.Getenv("JWT_EXPIRED")
	if expiryStr == "" {
		expiryStr = "30m"
	}

	duration, err := ParseExpiry(expiryStr)
	if err != nil {
		return "", err
	}

	claims := model.ClaimsModel{
		UserID:   user.ID,
		Role:     user.Role,
		Username: user.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   strconv.Itoa(user.ID),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func CreateRefreshToken(
	ctx context.Context,
	user model.User,
	rdb *redis.Client,
	issued_at *time.Time,
) (string, error) {
	if rdb == nil {
		return "", errors.New("redis client required for refresh token")
	}
	if issued_at == nil {
		issued_at = &time.Time{}
	}

	secret := os.Getenv("JWT_REFRESH_SECRET")
	if secret == "" {
		return "", errors.New("JWT_REFRESH_SECRET missing")
	}

	expiryStr := os.Getenv("JWT_REFRESH_EXPIRED")
	if expiryStr == "" {
		expiryStr = "7d"
	}

	duration, err := ParseExpiry(expiryStr)
	if err != nil {
		return "", err
	}

	jti := uuid.NewString()
	expiresAt := time.Now().Add(duration)

	claims := model.ClaimsModel{
		UserID:   user.ID,
		Role:     user.Role,
		Username: user.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "auth-service",
			ID:        jti,
			Subject:   strconv.Itoa(user.ID),
			IssuedAt:  jwt.NewNumericDate(*issued_at),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}

	key := refreshKey(jti)
	if err := rdb.Set(ctx, key, hashToken(tokenString), duration).Err(); err != nil {
		return "", err
	}

	return tokenString, nil
}

func ValidateAccessToken(tokenString string) (*model.ClaimsModel, error) {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		return nil, errors.New("JWT_SECRET missing")
	}

	token, err := jwt.ParseWithClaims(
		tokenString,
		&model.ClaimsModel{},
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(secret), nil
		},
	)
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*model.ClaimsModel)
	if !ok || !token.Valid {
		return nil, errors.New("invalid access token")
	}

	return claims, nil
}

func ValidateRefreshToken(
	ctx context.Context,
	refreshToken string,
	rdb *redis.Client,
) (*model.ClaimsModel, error) {
	secret := os.Getenv("JWT_REFRESH_SECRET")
	if secret == "" {
		return nil, errors.New("JWT_REFRESH_SECRET missing")
	}

	token, err := jwt.ParseWithClaims(
		refreshToken,
		&model.ClaimsModel{},
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(secret), nil
		},
	)
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*model.ClaimsModel)
	if !ok || !token.Valid {
		return nil, errors.New("invalid refresh token")
	}

	jti := claims.ID
	if jti == "" {
		return nil, errors.New("refresh token missing jti")
	}

	key := refreshKey(jti)
	_, err = rdb.Get(ctx, key).Result()
	if err == nil {
		return claims, nil
	}

	if err == redis.Nil {
		usedKey := "refresh:used:" + jti
		if _, err := rdb.Get(ctx, usedKey).Result(); err == nil {
			// paksa logout
			RevokeRefreshToken(ctx, refreshToken, rdb)
			return nil, errors.New("refresh token reuse detected")
		}
		return nil, errors.New("refresh token expired or revoked")
	}

	return nil, err
}

func RevokeRefreshToken(ctx context.Context, refreshToken string, rdb *redis.Client) error {
	claims, err := ValidateRefreshToken(ctx, refreshToken, rdb)
	if err != nil {
		return errors.New("refresh token invalid")
	}

	if rdb == nil {
		return errors.New("redis client required")
	}
	jti := claims.ID
	return rdb.Del(ctx, refreshKey(jti)).Err()
}

func RefreshRotation(
	ctx context.Context,
	refreshToken string,
	user model.User,
	rdb *redis.Client,
) (string, error) {
	claims, err := ValidateRefreshToken(ctx, refreshToken, rdb)
	if err != nil {
		return "", err
	}

	oldJTI := claims.ID
	if oldJTI == "" {
		return "", errors.New("refresh token missing jti")
	}

	issuedAt := claims.IssuedAt.Time
	if time.Now().After(issuedAt.Add(30 * 24 * time.Hour)) {
		_ = rdb.Del(ctx, refreshKey(oldJTI)).Err()
		return "", errors.New("session expired, please login again")
	}

	if err := rdb.Del(ctx, refreshKey(oldJTI)).Err(); err != nil {
		return "", err
	}

	reuseKey := "refresh:used:" + oldJTI
	if err := rdb.Set(ctx, reuseKey, "1", 2*time.Minute).Err(); err != nil {
		return "", err
	}

	newToken, err := CreateRefreshToken(ctx, user, rdb, &issuedAt)
	if err != nil {
		return "", err
	}

	return newToken, nil
}
