package middleware

import (
	"testMM/internal/auth"
	"testMM/internal/config"

	"github.com/gin-gonic/gin"
)

type Set struct {
	CORS      gin.HandlerFunc
	AccessJWT gin.HandlerFunc
}

func NewSet(cfg config.Config, authSvc *auth.Service) *Set {
	return &Set{
		CORS:      NewCORS(cfg),
		AccessJWT: NewAccessJWT(cfg, authSvc),
	}
}
