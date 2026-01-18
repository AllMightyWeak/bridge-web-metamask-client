package handlers

import (
	"net/http"
	"strings"
	"testMM/backend/internal/scan"

	"github.com/ethereum/go-ethereum/common"
	"github.com/gin-gonic/gin"
)

type ScanContactReq struct {
	ContactAddr string `json:"contactAddr"`
	Network     string `json:"network"`     // contact_network
	FromBlock   uint64 `json:"fromBlock"`   // 0 = auto
	ToBlock     uint64 `json:"toBlock"`     // 0 = latest
	NFTContract string `json:"nftContract"` // optional override
}

func (h *Handlers) ScanByContact(c *gin.Context) {
	var req ScanContactReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad json: " + err.Error()})
		return
	}

	req.ContactAddr = strings.TrimSpace(req.ContactAddr)
	if !common.IsHexAddress(req.ContactAddr) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid contactAddr"})
		return
	}

	netKey := strings.ToLower(strings.TrimSpace(req.Network))
	if netKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "network is required"})
		return
	}

	bridgeAddr, ok := h.Cfg.BridgeByNetwork[netKey]
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bridge is not configured for network: " + req.Network})
		return
	}

	if h.TxScanner == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "TxScanner is not configured"})
		return
	}

	// ✅ sender = тот, кто вызывает (из JWT)
	sender := c.MustGet("address").(common.Address)
	// ✅ recipient = выбранный контакт
	recipient := common.HexToAddress(req.ContactAddr)

	out, err := h.TxScanner.ScanTransfers(c.Request.Context(), scan.TxScanParams{
		NetworkKey:      netKey,
		BridgeAddr:      common.HexToAddress(bridgeAddr),
		Sender:          sender,
		RecipientFilter: recipient,
		FromBlock:       req.FromBlock,
		ToBlock:         req.ToBlock,
		NFTContract:     strings.TrimSpace(req.NFTContract),
	})
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, out)
}
