package auth

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testMM/backend/internal/config"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ofstudio/go-api-epgu/esia/aas"
	"github.com/ofstudio/go-api-epgu/esia/signature"
)

// EsiaService — OAuth2-клиент ЕСИА на базе go-api-epgu/esia/aas.
type EsiaService struct {
	client      *aas.Client
	redirectURI string
	scope       string
	// states хранит state → true (одноразовый, для CSRF-защиты)
	states *NonceStore // переиспользуем тот же NonceStore из service.go
}

// NewEsiaService создаёт EsiaService.
// Использует LocalCryptoPro для подписи (КриптоПро CSP должен быть установлен на сервере).
func NewEsiaService(cfg config.Config) (*EsiaService, error) {
	if cfg.EsiaClientID == "" {
		return nil, errors.New("ESIA_CLIENT_ID не задан")
	}
	if cfg.EsiaURI == "" {
		return nil, errors.New("ESIA_URI не задан")
	}
	if cfg.EsiaRedirectURI == "" {
		return nil, errors.New("ESIA_REDIRECT_URI не задан")
	}
	if cfg.EsiaCspContainer == "" || cfg.EsiaCertHash == "" {
		return nil, errors.New("ESIA_CSP_CONTAINER и ESIA_CERT_HASH обязательны")
	}

	signer := signature.NewLocalCryptoPro(
		cfg.EsiaCspTestPath,
		cfg.EsiaCspContainer,
		cfg.EsiaCertHash,
	)

	client := aas.NewClient(cfg.EsiaURI, cfg.EsiaClientID, signer)

	return &EsiaService{
		client:      client,
		redirectURI: cfg.EsiaRedirectURI,
		scope:       cfg.EsiaScope,
		states:      NewNonceStore(cfg.NonceTTL),
	}, nil
}

// AuthURL формирует URL редиректа на страницу ЕСИА.
// Возвращает (authURL, state, error).
func (s *EsiaService) AuthURL() (string, string, error) {
	authURI, err := s.client.AuthURI(s.scope, s.redirectURI, nil)
	if err != nil {
		return "", "", fmt.Errorf("esia AuthURI: %w", err)
	}

	// Извлекаем state из сформированного URL (библиотека генерирует его сама)
	parsed, err := url.Parse(authURI)
	if err != nil {
		return "", "", fmt.Errorf("parse authURI: %w", err)
	}
	state := parsed.Query().Get("state")
	if state == "" {
		return "", "", errors.New("state отсутствует в authURI")
	}

	// Сохраняем state для последующей проверки в callback
	s.states.Put("esia_state:"+state, NonceEntry{Nonce: state})

	return authURI, state, nil
}

// ExchangeCode обменивает code+state на маркер доступа ЕСИА.
// Возвращает esiaUserID (OID) пользователя.
func (s *EsiaService) ExchangeCode(code, state string) (string, error) {
	// Проверяем state (CSRF-защита)
	stateKey := "esia_state:" + state
	_, ok := s.states.Get(stateKey)
	if !ok {
		return "", errors.New("неверный или устаревший state")
	}
	s.states.Delete(stateKey)

	// Обмениваем code на токен
	tokenResp, err := s.client.TokenExchange(code, s.scope, s.redirectURI)
	if err != nil {
		return "", fmt.Errorf("TokenExchange: %w", err)
	}

	// Извлекаем OID из id_token (JWT без верификации подписи — OID публичен)
	oid, err := extractOIDFromIDToken(tokenResp.IdToken)
	if err != nil {
		return "", fmt.Errorf("извлечение OID: %w", err)
	}

	return oid, nil
}

// extractOIDFromIDToken — извлекает OID пользователя из id_token ЕСИА.
// id_token — это JWT, в котором subject (sub) содержит OID.
// Подпись не верифицируем — это делает ЕСИА на этапе TokenExchange.
func extractOIDFromIDToken(idToken string) (string, error) {
	idToken = strings.TrimSpace(idToken)
	if idToken == "" {
		return "", errors.New("пустой id_token")
	}

	// Парсим без верификации подписи (токен уже получен от ЕСИА напрямую)
	p := jwt.NewParser()
	token, _, err := p.ParseUnverified(idToken, jwt.MapClaims{})
	if err != nil {
		return "", fmt.Errorf("JWT parse: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("неверный формат claims")
	}

	// OID может быть в "sub" или "urn:esia:sbj_id"
	if sub, ok := claims["sub"]; ok {
		return fmt.Sprintf("%v", sub), nil
	}
	if sbj, ok := claims["urn:esia:sbj_id"]; ok {
		return fmt.Sprintf("%v", sbj), nil
	}

	return "", errors.New("OID не найден в id_token")
}
