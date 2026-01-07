package middleware

import (
	"net/http"
	"testMM/internal/config"

	"github.com/gin-gonic/gin"
)

func NewCORS(cfg config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin != "" {
			if len(cfg.AllowedOrigin) == 0 {
				c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
			} else {
				if _, ok := cfg.AllowedOrigin[origin]; ok {
					c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
				}
			}
			c.Writer.Header().Set("Vary", "Origin")
			c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		}

		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}
