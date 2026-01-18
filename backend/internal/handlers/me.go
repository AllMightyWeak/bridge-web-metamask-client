package handlers

import (
	"net/http"
	"testMM/backend/internal/eth"

	"github.com/ethereum/go-ethereum/common"
	"github.com/gin-gonic/gin"
)

func (h *Handlers) Me(c *gin.Context) {
	addr := c.MustGet("address").(common.Address)
	chainID := c.MustGet("chainId").(uint64)

	wei, err := h.Eth.BalanceWei(c.Request.Context(), chainID, addr)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "rpc balance failed: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"address": addr.Hex(),
		"chainId": chainID,
		"balance": eth.WeiToEthString(wei),
		"unit":    "ETH",
	})
}
