package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

type siweInitReq struct {
	Address string `json:"address"`
	ChainID uint64 `json:"chainId"`
}

type siweInitResp struct {
	Nonce     string `json:"nonce"`
	Message   string `json:"message"`
	ExpiresAt string `json:"expiresAt"`
	Domain    string `json:"domain"`
	URI       string `json:"uri"`
}

func (h *Handlers) SiweInit(c *gin.Context) {
	var req siweInitReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad json"})
		return
	}

	origin := c.GetHeader("Origin")
	res, err := h.Auth.InitSIWE(origin, req.Address, req.ChainID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, siweInitResp{
		Nonce:     res.Nonce,
		Message:   res.Message,
		ExpiresAt: res.ExpiresAt.UTC().Format(time.RFC3339),
		Domain:    res.Domain,
		URI:       res.URI,
	})
}

type siweVerifyReq struct {
	Message   string `json:"message"`
	Signature string `json:"signature"`
}

type siweVerifyResp struct {
	Address        string `json:"address"`
	ChainID        uint64 `json:"chainId"`
	AccessToken    string `json:"accessToken"`
	AccessExpires  string `json:"accessExpires"`
	RefreshToken   string `json:"refreshToken"`
	RefreshExpires string `json:"refreshExpires"`
}

func (h *Handlers) SiweVerify(c *gin.Context) {
	var req siweVerifyReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad json"})
		return
	}

	vr, err := h.Auth.VerifySIWE(req.Message, req.Signature)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// по требованию: подключение к Postgres после успешной авторизации
	if _, err := h.PG.Pool(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db init failed: " + err.Error()})
		return
	}

	t, err := h.Auth.IssueTokens(vr.Address, vr.ChainID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, siweVerifyResp{
		Address:        vr.Address,
		ChainID:        vr.ChainID,
		AccessToken:    t.AccessToken,
		AccessExpires:  t.AccessExp.UTC().Format(time.RFC3339),
		RefreshToken:   t.RefreshToken,
		RefreshExpires: t.RefreshExp.UTC().Format(time.RFC3339),
	})
}

type refreshReq struct {
	RefreshToken string `json:"refreshToken"`
}

type refreshResp struct {
	AccessToken    string `json:"accessToken"`
	AccessExpires  string `json:"accessExpires"`
	RefreshToken   string `json:"refreshToken"`
	RefreshExpires string `json:"refreshExpires"`
}

func (h *Handlers) Refresh(c *gin.Context) {
	var req refreshReq
	if err := c.ShouldBindJSON(&req); err != nil || req.RefreshToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad json"})
		return
	}

	t, err := h.Auth.RotateRefresh(req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, refreshResp{
		AccessToken:    t.AccessToken,
		AccessExpires:  t.AccessExp.UTC().Format(time.RFC3339),
		RefreshToken:   t.RefreshToken,
		RefreshExpires: t.RefreshExp.UTC().Format(time.RFC3339),
	})
}

func (h *Handlers) Logout(c *gin.Context) {
	var req refreshReq
	if err := c.ShouldBindJSON(&req); err != nil || req.RefreshToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad json"})
		return
	}
	h.Auth.RevokeRefresh(req.RefreshToken)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
