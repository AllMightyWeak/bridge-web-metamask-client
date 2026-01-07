package handlers

import (
	"net/http"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/gin-gonic/gin"
)

type AddContactRequest struct {
	Name      string `json:"name" binding:"required"`
	Address   string `json:"address" binding:"required"`
	Network   string `json:"network" binding:"required"`
	PublicKey string `json:"public_key" binding:"required"`
}

func (h *Handlers) AddContact(c *gin.Context) {
	userAddr := c.MustGet("address").(common.Address).Hex() // user_pub_key

	var req AddContactRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !common.IsHexAddress(req.Address) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid contact address"})
		return
	}

	if err := h.Contacts.Insert(
		c.Request.Context(),
		strings.ToLower(userAddr),
		req.PublicKey,
		strings.ToLower(req.Address),
		req.Name,
		req.Network,
	); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"contact_addr": strings.ToLower(req.Address)})
}

func (h *Handlers) GetContacts(c *gin.Context) {
	userAddr := c.MustGet("address").(common.Address).Hex() // user_pub_key

	items, err := h.Contacts.List(c.Request.Context(), strings.ToLower(userAddr))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"contacts": items})
}
