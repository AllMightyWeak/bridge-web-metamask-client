package handlers

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/gin-gonic/gin"
)

func (h *Handlers) GetNFTs(c *gin.Context) {
	addr := c.MustGet("address").(common.Address)

	if h.NftWatcher == nil {
		c.JSON(503, gin.H{"error": "nft watcher is not configured"})
		return
	}

	h.NftWatcher.Register(addr)

	items, lastErr := h.NftWatcher.GetOrScanNow(c.Request.Context(), addr)
	c.JSON(200, gin.H{
		"owner": addr.Hex(),
		"nfts":  items,
		"error": lastErr,
	})
}
