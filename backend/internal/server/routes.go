package server

import (
	"testMM/backend/internal/handlers"
	"testMM/backend/internal/middleware"

	"github.com/gin-gonic/gin"
)

func RegisterRoutes(r *gin.Engine, h *handlers.Handlers, mw *middleware.Set) {
	r.GET("/health", h.Health)
	r.GET("/chains", h.Chains)

	auth := r.Group("/auth")
	auth.POST("/siwe/init", h.SiweInit)
	auth.POST("/siwe/verify", h.SiweVerify)
	auth.POST("/refresh", h.Refresh)
	auth.POST("/logout", h.Logout)

	esia := auth.Group("/esia")
	esia.GET("/login", h.EsiaLogin)       // редирект на Госуслуги
	esia.GET("/callback", h.EsiaCallback) // callback от Госуслуг

	// ← ДОБАВИТЬ: привязка кошелька к ЕСИА-аккаунту
	esia.POST("/wallet/init", h.EsiaWalletLinkInit)
	esia.POST("/wallet/verify", h.EsiaWalletLinkVerify)

	protected := r.Group("/")
	protected.Use(mw.AccessJWT)

	protected.GET("/me", h.Me)
	protected.POST("/contacts", h.AddContact)
	protected.GET("/contacts", h.GetContacts)
	protected.POST("/files/send", h.SendFile)
	protected.GET("/nfts", h.GetNFTs)
	protected.POST("/scan/contact", h.ScanByContact)

}
