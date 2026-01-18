package middleware

import (
	"net/http"
	"strings"
	"testMM/backend/internal/auth"
	"testMM/backend/internal/config"

	"github.com/ethereum/go-ethereum/common"
	"github.com/gin-gonic/gin"
)

func NewAccessJWT(cfg config.Config, authSvc *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.GetHeader("Authorization")
		if !strings.HasPrefix(h, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing bearer token"})
			return
		}
		raw := strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))

		claims, err := authSvc.ParseAccess(raw)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}
		if !common.IsHexAddress(claims.Subject) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid subject"})
			return
		}
		if _, ok := cfg.RPCByChainID[claims.ChainID]; !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unsupported chainId"})
			return
		}

		c.Set("address", common.HexToAddress(claims.Subject))
		c.Set("chainId", claims.ChainID)
		c.Next()
	}
}
