package auth

import (
	"crypto/sha256"
	"errors"
	"net/url"
	"strings"
	"sync"
	"testMM/backend/internal/config"
	"testMM/backend/internal/util"

	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/spruceid/siwe-go"
)

type Service struct {
	cfg     config.Config
	jwt     *JWTManager
	nonces  *NonceStore
	refresh *RefreshStore
}

func NewService(cfg config.Config) *Service {
	return &Service{
		cfg:     cfg,
		jwt:     NewJWTManager(cfg),
		nonces:  NewNonceStore(cfg.NonceTTL),
		refresh: NewRefreshStore(cfg.RefreshTTL),
	}
}

type InitResult struct {
	Nonce     string
	Message   string
	ExpiresAt time.Time
	Domain    string
	URI       string
}

func (s *Service) InitSIWE(origin string, address string, chainID uint64) (InitResult, error) {
	if !common.IsHexAddress(address) {
		return InitResult{}, errors.New("invalid address")
	}
	if _, ok := s.cfg.RPCByChainID[chainID]; !ok {
		return InitResult{}, errors.New("unsupported chainId")
	}

	origin = strings.TrimSpace(origin)
	if origin == "" {
		return InitResult{}, errors.New("missing Origin header")
	}
	if len(s.cfg.AllowedOrigin) > 0 {
		if _, ok := s.cfg.AllowedOrigin[origin]; !ok {
			return InitResult{}, errors.New("origin not allowed")
		}
	}

	u, err := url.Parse(origin)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return InitResult{}, errors.New("bad Origin")
	}

	domain := u.Host
	uri := origin

	nonce, err := util.RandomBase64URL(16)
	if err != nil {
		return InitResult{}, err
	}

	now := time.Now().UTC()
	exp := now.Add(s.cfg.NonceTTL)

	statement := "Sign in to DemoApp"
	msg := BuildSIWEMessage(domain, common.HexToAddress(address).Hex(), uri, statement, chainID, nonce, now, exp)

	key := nonceKey(address, chainID)
	s.nonces.Put(key, NonceEntry{
		Nonce:     nonce,
		Domain:    domain,
		URI:       uri,
		ChainID:   chainID,
		ExpiresAt: exp,
	})

	return InitResult{Nonce: nonce, Message: msg, ExpiresAt: exp, Domain: domain, URI: uri}, nil
}

type VerifyResult struct {
	Address string
	ChainID uint64
}

func (s *Service) VerifySIWE(message string, signature string) (VerifyResult, error) {
	msg, err := siwe.ParseMessage(message)
	if err != nil {
		return VerifyResult{}, errors.New("invalid siwe message")
	}

	addr := msg.GetAddress()
	chainID := uint64(msg.GetChainID())
	if _, ok := s.cfg.RPCByChainID[chainID]; !ok {
		return VerifyResult{}, errors.New("unsupported chainId")
	}

	key := nonceKey(addr.Hex(), chainID)
	entry, ok := s.nonces.Get(key)
	if !ok || time.Now().After(entry.ExpiresAt) {
		return VerifyResult{}, errors.New("nonce expired or not found")
	}

	if entry.Domain != msg.GetDomain() {
		return VerifyResult{}, errors.New("domain mismatch")
	}

	uriURI := msg.GetURI()
	msgURI := uriURI.String()
	if util.NormalizeURL(entry.URI) != util.NormalizeURL(msgURI) {
		return VerifyResult{}, errors.New("uri mismatch")
	}

	if entry.Nonce != msg.GetNonce() {
		return VerifyResult{}, errors.New("nonce mismatch")
	}

	d := entry.Domain
	n := entry.Nonce
	if _, err := msg.Verify(signature, &d, &n, nil); err != nil {
		return VerifyResult{}, errors.New("invalid signature")
	}

	s.nonces.Delete(key)
	return VerifyResult{Address: addr.Hex(), ChainID: chainID}, nil
}

type Tokens struct {
	AccessToken  string
	AccessExp    time.Time
	RefreshToken string
	RefreshExp   time.Time
}

func (s *Service) IssueTokens(address string, chainID uint64) (Tokens, error) {
	access, accessExp, err := s.jwt.IssueAccess(address, chainID)
	if err != nil {
		return Tokens{}, err
	}
	refresh, refreshExp, err := s.refresh.Create(address, chainID)
	if err != nil {
		return Tokens{}, err
	}
	return Tokens{AccessToken: access, AccessExp: accessExp, RefreshToken: refresh, RefreshExp: refreshExp}, nil
}

func (s *Service) RotateRefresh(oldRefresh string) (Tokens, error) {
	sess, ok := s.refresh.Consume(oldRefresh)
	if !ok || time.Now().After(sess.ExpiresAt) {
		return Tokens{}, errors.New("invalid refresh token")
	}
	return s.IssueTokens(sess.Address, sess.ChainID)
}

func (s *Service) RevokeRefresh(refresh string) {
	s.refresh.Revoke(refresh)
}

func (s *Service) ParseAccess(token string) (*AccessClaims, error) {
	return s.jwt.ParseAccess(token)
}

func nonceKey(address string, chainID uint64) string {
	return strings.ToLower(strings.TrimSpace(address)) + ":" + util.UintToString(chainID)
}

/* ---------------- Nonce store ---------------- */

type NonceEntry struct {
	Nonce     string
	Domain    string
	URI       string
	ChainID   uint64
	ExpiresAt time.Time
}

type NonceStore struct {
	mu sync.Mutex
	m  map[string]NonceEntry
}

func NewNonceStore(_ time.Duration) *NonceStore {
	return &NonceStore{m: make(map[string]NonceEntry)}
}

func (s *NonceStore) Put(key string, e NonceEntry) {
	s.mu.Lock()
	s.m[key] = e
	s.mu.Unlock()
}

func (s *NonceStore) Get(key string) (NonceEntry, bool) {
	s.mu.Lock()
	e, ok := s.m[key]
	s.mu.Unlock()
	return e, ok
}

func (s *NonceStore) Delete(key string) {
	s.mu.Lock()
	delete(s.m, key)
	s.mu.Unlock()
}

/* ---------------- Refresh store (rotation) ---------------- */

type RefreshSession struct {
	Address   string
	ChainID   uint64
	ExpiresAt time.Time
	CreatedAt time.Time
	LastUsed  time.Time
}

type RefreshStore struct {
	ttl time.Duration
	mu  sync.Mutex
	m   map[[32]byte]RefreshSession
}

func NewRefreshStore(ttl time.Duration) *RefreshStore {
	return &RefreshStore{ttl: ttl, m: make(map[[32]byte]RefreshSession)}
}

func (s *RefreshStore) Create(address string, chainID uint64) (token string, exp time.Time, err error) {
	token, err = util.RandomBase64URL(32)
	if err != nil {
		return "", time.Time{}, err
	}
	exp = time.Now().Add(s.ttl)

	h := sha256.Sum256([]byte(token))

	s.mu.Lock()
	s.m[h] = RefreshSession{
		Address:   address,
		ChainID:   chainID,
		ExpiresAt: exp,
		CreatedAt: time.Now(),
		LastUsed:  time.Now(),
	}
	s.mu.Unlock()

	return token, exp, nil
}

func (s *RefreshStore) Consume(token string) (RefreshSession, bool) {
	h := sha256.Sum256([]byte(token))
	s.mu.Lock()
	sess, ok := s.m[h]
	if ok {
		delete(s.m, h)
	}
	s.mu.Unlock()
	return sess, ok
}

func (s *RefreshStore) Revoke(token string) {
	h := sha256.Sum256([]byte(token))
	s.mu.Lock()
	delete(s.m, h)
	s.mu.Unlock()
}
