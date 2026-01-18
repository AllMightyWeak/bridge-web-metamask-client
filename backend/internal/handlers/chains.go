package handlers

import "github.com/gin-gonic/gin"

func (h *Handlers) Chains(c *gin.Context) {
	out := make([]gin.H, 0, len(h.Cfg.RPCByChainID))
	for chainID := range h.Cfg.RPCByChainID {
		out = append(out, gin.H{"chainId": chainID})
	}
	c.JSON(200, gin.H{"chains": out})
}
