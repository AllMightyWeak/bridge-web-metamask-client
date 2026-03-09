package handlers

import (
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/gin-gonic/gin"
)

// --- Init: генерируем nonce для подписи ---

type esiaWalletInitReq struct {
	EsiaUserID string `json:"esiaUserID"`
	Address    string `json:"address"`
	ChainID    uint64 `json:"chainId"`
}

type esiaWalletInitResp struct {
	Nonce   string `json:"nonce"`
	Message string `json:"message"`
}

// POST /auth/esia/wallet/init
func (h *Handlers) EsiaWalletLinkInit(c *gin.Context) {
	var req esiaWalletInitReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad json"})
		return
	}

	if req.EsiaUserID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "esiaUserID is required"})
		return
	}
	if !common.IsHexAddress(req.Address) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid ethereum address"})
		return
	}
	if _, ok := h.Cfg.RPCByChainID[req.ChainID]; !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported chainId"})
		return
	}

	nonce, message, err := h.Auth.InitWalletLink(req.EsiaUserID, req.Address)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, esiaWalletInitResp{
		Nonce:   nonce,
		Message: message,
	})
}

// --- Verify: проверяем подпись, сохраняем связь, выдаём JWT ---

type esiaWalletVerifyReq struct {
	EsiaUserID string `json:"esiaUserID"`
	Address    string `json:"address"`
	ChainID    uint64 `json:"chainId"`
	Message    string `json:"message"`
	Signature  string `json:"signature"`
}

type esiaWalletVerifyResp struct {
	Address        string `json:"address"`
	ChainID        uint64 `json:"chainId"`
	AccessToken    string `json:"accessToken"`
	AccessExpires  string `json:"accessExpires"`
	RefreshToken   string `json:"refreshToken"`
	RefreshExpires string `json:"refreshExpires"`
	EsiaUserID     string `json:"esiaUserID"`
}

// POST /auth/esia/wallet/verify
func (h *Handlers) EsiaWalletLinkVerify(c *gin.Context) {
	var req esiaWalletVerifyReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad json"})
		return
	}

	if req.EsiaUserID == "" || req.Address == "" || req.Message == "" || req.Signature == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "esiaUserID, address, message, signature are required"})
		return
	}
	if _, ok := h.Cfg.RPCByChainID[req.ChainID]; !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported chainId"})
		return
	}

	// 1. Проверяем подпись через ecrecover
	if err := h.Auth.VerifyWalletLink(req.EsiaUserID, req.Address, req.Message, req.Signature); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// 2. Сохраняем связь ЕСИА → кошелёк в базу
	if err := h.EsiaLinks.SaveLink(c.Request.Context(), req.EsiaUserID, req.Address, req.ChainID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save wallet link: " + err.Error()})
		return
	}

	// 3. Инициализируем пул Postgres (как в SiweVerify)
	if _, err := h.PG.Pool(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db init failed: " + err.Error()})
		return
	}

	// 4. Регистрируем адрес в NFT watcher
	h.NftWatcher.Register(common.HexToAddress(req.Address))

	// 5. Выдаём JWT (тот же IssueTokens что и при SIWE)
	t, err := h.Auth.IssueTokens(req.Address, req.ChainID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, esiaWalletVerifyResp{
		Address:        common.HexToAddress(req.Address).Hex(),
		ChainID:        req.ChainID,
		AccessToken:    t.AccessToken,
		AccessExpires:  t.AccessExp.UTC().Format(time.RFC3339),
		RefreshToken:   t.RefreshToken,
		RefreshExpires: t.RefreshExp.UTC().Format(time.RFC3339),
		EsiaUserID:     req.EsiaUserID,
	})
}
