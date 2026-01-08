package server

import (
	"testMM/internal/handlers"
	"testMM/internal/middleware"

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

	protected := r.Group("/")
	protected.Use(mw.AccessJWT)

	protected.GET("/me", h.Me)
	protected.POST("/contacts", h.AddContact)
	protected.GET("/contacts", h.GetContacts)
	protected.POST("/files/send", h.SendFile)
}
