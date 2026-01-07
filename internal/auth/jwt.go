package auth

import (
	"errors"
	"testMM/internal/config"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type AccessClaims struct {
	Typ     string `json:"typ"`
	ChainID uint64 `json:"chain_id"`
	jwt.RegisteredClaims
}

type JWTManager struct {
	secret    []byte
	accessTTL time.Duration
}

func NewJWTManager(cfg config.Config) *JWTManager {
	return &JWTManager{secret: []byte(cfg.AccessSecret), accessTTL: cfg.AccessTTL}
}

func (m *JWTManager) IssueAccess(address string, chainID uint64) (token string, exp time.Time, err error) {
	exp = time.Now().Add(m.accessTTL)

	claims := AccessClaims{
		Typ:     "access",
		ChainID: chainID,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   address,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err = t.SignedString(m.secret)
	return token, exp, err
}

func (m *JWTManager) ParseAccess(token string) (*AccessClaims, error) {
	var claims AccessClaims
	parsed, err := jwt.ParseWithClaims(token, &claims, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, errors.New("unexpected signing method")
		}
		return m.secret, nil
	})
	if err != nil || !parsed.Valid {
		return nil, errors.New("invalid token")
	}
	if claims.Typ != "access" {
		return nil, errors.New("invalid token type")
	}
	return &claims, nil
}
