package handlers

import "github.com/gin-gonic/gin"

func (h *Handlers) Health(c *gin.Context) {
	c.JSON(200, gin.H{"ok": true})
}
