package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/golang-jwt/jwt/v5"
)

type Server struct {
	jwtSecret []byte
	rpc       *ethclient.Client

	mu     sync.Mutex
	nonces map[string]nonceEntry // key: lowercased address
}

type nonceEntry struct {
	Nonce     string
	ExpiresAt time.Time
}

func main() {
	jwtSecret := "JmwsiRQbqojcvDzbNHJFOCTMN0vifrd0"
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET env is required")
	}

	rpcURL := "" // например: https://mainnet.infura.io/v3/...
	if rpcURL == "" {
		log.Fatal("RPC_URL env is required")
	}

	rpc, err := ethclient.Dial(rpcURL)
	if err != nil {
		log.Fatalf("failed to connect RPC: %v", err)
	}

	s := &Server{
		jwtSecret: []byte(jwtSecret),
		rpc:       rpc,
		nonces:    make(map[string]nonceEntry),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/auth/nonce", s.handleNonce)
	mux.HandleFunc("/auth/login", s.handleLogin)
	mux.HandleFunc("/me", s.withJWT(s.handleMe))

	// CORS (для демо; в проде лучше ограничить Origin)
	handler := withCORS(mux)

	addr := ":8080"
	log.Printf("listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, handler))
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

type nonceReq struct {
	Address string `json:"address"`
}

type nonceResp struct {
	Nonce   string `json:"nonce"`
	Message string `json:"message"`
	// message — то, что надо подписать на фронте
}

func (s *Server) handleNonce(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}

	var req nonceReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad json"})
		return
	}

	addr := strings.ToLower(strings.TrimSpace(req.Address))
	if !common.IsHexAddress(addr) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid address"})
		return
	}

	nonce, err := generateNonce(16)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "nonce gen failed"})
		return
	}

	// Сообщение для подписи. Для продакшена лучше сделать SIWE (EIP-4361).
	message := fmt.Sprintf(
		"Sign in to DemoApp\n\nAddress: %s\nNonce: %s\nIssued At: %s",
		common.HexToAddress(addr).Hex(),
		nonce,
		time.Now().UTC().Format(time.RFC3339),
	)

	s.mu.Lock()
	s.nonces[addr] = nonceEntry{
		Nonce:     nonce,
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, nonceResp{Nonce: nonce, Message: message})
}

type loginReq struct {
	Address   string `json:"address"`
	Signature string `json:"signature"` // hex (0x...)
	Message   string `json:"message"`   // то, что подписали (должно совпасть с выданным)
}

type loginResp struct {
	Token   string `json:"token"`
	Address string `json:"address"`
	Expires string `json:"expires"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}

	var req loginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad json"})
		return
	}

	addrStr := strings.ToLower(strings.TrimSpace(req.Address))
	if !common.IsHexAddress(addrStr) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid address"})
		return
	}
	address := common.HexToAddress(addrStr)

	// Проверяем nonce (и что message содержит тот nonce)
	s.mu.Lock()
	entry, ok := s.nonces[addrStr]
	s.mu.Unlock()

	if !ok || time.Now().After(entry.ExpiresAt) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "nonce expired or not found"})
		return
	}
	if !strings.Contains(req.Message, "Nonce: "+entry.Nonce) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "message nonce mismatch"})
		return
	}

	// Верификация подписи: recover address из signature + message
	recovered, err := recoverAddressFromSignature(req.Message, req.Signature)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "bad signature"})
		return
	}
	if recovered != address {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "signature does not match address"})
		return
	}

	// Одноразовый nonce — после логина удаляем
	s.mu.Lock()
	delete(s.nonces, addrStr)
	s.mu.Unlock()

	// JWT
	exp := time.Now().Add(2 * time.Hour)
	token, err := s.issueJWT(address.Hex(), exp)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "jwt failed"})
		return
	}

	writeJSON(w, http.StatusOK, loginResp{
		Token:   token,
		Address: address.Hex(),
		Expires: exp.UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	addr := r.Context().Value(ctxKeyAddress{}).(common.Address)

	wei, err := s.rpc.BalanceAt(r.Context(), addr, nil)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": "rpc balance failed"})
		return
	}

	balanceEth := weiToEthString(wei)

	writeJSON(w, http.StatusOK, map[string]any{
		"address": addr.Hex(),
		"balance": balanceEth,
		"unit":    "ETH",
	})
}

/* ---------------- JWT middleware ---------------- */

type ctxKeyAddress struct{}

func (s *Server) withJWT(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		if !strings.HasPrefix(h, "Bearer ") {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "missing bearer token"})
			return
		}
		raw := strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))

		claims := jwt.MapClaims{}
		parsed, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
			if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
				return nil, errors.New("unexpected signing method")
			}
			return s.jwtSecret, nil
		})
		if err != nil || !parsed.Valid {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid token"})
			return
		}

		sub, _ := claims["sub"].(string)
		if !common.IsHexAddress(sub) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid subject"})
			return
		}

		ctx := context.WithValue(r.Context(), ctxKeyAddress{}, common.HexToAddress(sub))
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func (s *Server) issueJWT(addressHex string, exp time.Time) (string, error) {
	claims := jwt.MapClaims{
		"sub": addressHex,
		"iat": time.Now().Unix(),
		"exp": exp.Unix(),
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString(s.jwtSecret)
}

/* ---------------- Signature utils ---------------- */

func recoverAddressFromSignature(message string, signatureHex string) (common.Address, error) {
	sig, err := hexutil.Decode(signatureHex)
	if err != nil {
		return common.Address{}, err
	}
	if len(sig) != 65 {
		return common.Address{}, errors.New("signature must be 65 bytes")
	}

	// MetaMask/ethers часто отдает V = 27/28; go-ethereum ждет 0/1
	if sig[64] >= 27 {
		sig[64] -= 27
	}
	if sig[64] != 0 && sig[64] != 1 {
		return common.Address{}, errors.New("invalid recovery id")
	}

	// EIP-191 prefix hash: "\x19Ethereum Signed Message:\n" + len(message) + message
	hash := accounts.TextHash([]byte(message))

	pub, err := crypto.SigToPub(hash, sig)
	if err != nil {
		return common.Address{}, err
	}
	return crypto.PubkeyToAddress(*pub), nil
}

/* ---------------- Helpers ---------------- */

func generateNonce(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func weiToEthString(wei *big.Int) string {
	// 1 ETH = 1e18 wei
	rat := new(big.Rat).SetInt(wei)
	den := new(big.Rat).SetInt(big.NewInt(1_000_000_000_000_000_000))
	rat.Quo(rat, den)
	// аккуратно строкой; для демо нормально
	return rat.FloatString(18)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
