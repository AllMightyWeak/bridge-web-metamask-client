package handlers

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testMM/backend/internal/cryptoenc"
	encryptionAbe "testMM/backend/internal/cryptoenc/abe"
	"testMM/backend/internal/ipfs"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
)

const nftABI = `[
  {
    "inputs": [
      {"internalType":"string","name":"_tokenURI","type":"string"}
    ],
    "name":"createToken",
    "outputs":[{"internalType":"uint256","name":"","type":"uint256"}],
    "stateMutability":"nonpayable",
    "type":"function"
  }
]`

type TxRequest struct {
	From    string `json:"from"`
	To      string `json:"to"`
	Data    string `json:"data"`    // 0x...
	Value   string `json:"value"`   // 0x0
	ChainID uint64 `json:"chainId"` // чтобы фронт мог проверить сеть
}

type ApprovePlan struct {
	BridgeAddr string `json:"bridgeAddr"`
	Network    string `json:"network"`
}

type TransferPlan struct {
	BridgeAddr      string `json:"bridgeAddr"`           // адрес bridge на текущей сети
	OwnerAddressInB string `json:"ownerAddressInChainB"` // получатель в сети B (адрес)
	Network         string `json:"network"`              // contact_network (для отладки/UI)
}

type SendFileResp struct {
	Cid       string `json:"cid"`
	Name      string `json:"name"`
	Size      int    `json:"size"`
	CreatedAt string `json:"created_at"`
	Gateway   string `json:"gateway,omitempty"`
	TokenURI  string `json:"token_uri"`

	Tx       TxRequest    `json:"tx"` // ✅ готовая транзакция для MetaMask
	Approve  ApprovePlan  `json:"approve"`
	Transfer TransferPlan `json:"transfer"`
}

// POST /files/send (protected)
func (h *Handlers) SendFile(c *gin.Context) {
	sender := c.MustGet("address").(common.Address).Hex()
	chainID := c.MustGet("chainId").(uint64)

	recipient := strings.TrimSpace(c.PostForm("recipient_address"))
	if !common.IsHexAddress(recipient) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid recipient_address"})
		return
	}

	// dept/role (FormData)
	deptStr := strings.TrimSpace(c.PostForm("dept"))
	roleStr := strings.TrimSpace(c.PostForm("role"))

	var dept int
	var role int

	if deptStr != "" {
		v, err := strconv.Atoi(deptStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid dept"})
			return
		}
		dept = v
	}
	if roleStr != "" {
		v, err := strconv.Atoi(roleStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid role"})
			return
		}
		role = v
	}
	// defaults (если фронт не прислал)

	noPolicy := (dept == -1 && role == -1)

	if !noPolicy {
		// validate ranges
		if dept < 0 || dept > 2 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "dept must be 0..2"})
			return
		}
		if role < 0 || role > 1 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "role must be 0..1"})
			return
		}

		fileHeader, err := c.FormFile("payload")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing payload file"})
			return
		}

		f, err := fileHeader.Open()
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "cannot open payload"})
			return
		}
		defer f.Close()

		payloadBytes, err := ioReadAllLimit(f, 25<<20) // 25MB
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// 1) достаем public key получателя из contacts текущего юзера
		info, err := h.Contacts.GetContactKeyInfo(
			c.Request.Context(),
			strings.ToLower(sender),
			strings.ToLower(recipient),
		)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				c.JSON(http.StatusNotFound, gin.H{"error": "recipient public key not found in contacts"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		netKey := strings.ToLower(strings.TrimSpace(info.Network))
		bridgeAddr, ok := h.Cfg.BridgeByNetwork[netKey]
		if !ok {
			c.JSON(400, gin.H{"error": "bridge is not configured for network: " + info.Network})
			return
		}

		pubECDSA, err := parsePubKey(info.PubKey)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "bad recipient public key: " + err.Error()})
			return
		}

		// 2) шифруем bytes получателя

		cipher, err := cryptoenc.EncryptBytes(pubECDSA, payloadBytes, fileHeader.Filename)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// 3) загружаем в IPFS (Pinata)
		pin, err := ipfs.NewFromEnv()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		name := fileHeader.Filename
		if name == "" {
			name = "document"
		}
		nameEnc := name + ".enc"

		up, err := pin.UploadBytes(nameEnc, cipher)
		if err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
			return
		}

		gateway := strings.TrimSpace(os.Getenv("PINATA_GATEWAY"))
		gwURL := ""
		if gateway != "" {
			gwURL = "https://" + gateway + "/ipfs/" + up.Data.Cid
		}

		// 4) CID -> tokenURI
		//    Обычно для NFT используют ipfs://CID
		tokenURI := "ipfs://" + up.Data.Cid
		if nameEnc != "" {
			tokenURI = tokenURI + "?name=" + url.QueryEscape(nameEnc)
		}

		encLink := encryptionAbe.EncryptLink(tokenURI, dept, role)
		tokenURI, err = encryptionAbe.MarshalEncryptedDataToString(encLink)
		tokenURI = tokenURI + "?name=" + url.QueryEscape(nameEnc)
		if err != nil {
			log.Println("error encrypting tokenURI: ", err)
		}

		// 5) Формируем calldata для createToken(owner, tokenURI)
		nftAddrStr := strings.TrimSpace(os.Getenv("NFT_ADDR"))
		if !common.IsHexAddress(nftAddrStr) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "NFT_ADDR env is missing or invalid"})
			return
		}
		nftAddr := common.HexToAddress(nftAddrStr)

		parsedABI, err := abi.JSON(strings.NewReader(nftABI))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "nft abi parse failed: " + err.Error()})
			return
		}

		data, err := parsedABI.Pack("createToken", tokenURI)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "abi pack failed: " + err.Error()})
			return
		}

		ownerB := strings.ToLower(strings.TrimSpace(recipient))

		// 6) Возвращаем tx request для MetaMask
		c.JSON(http.StatusOK, SendFileResp{
			Cid:       up.Data.Cid,
			Name:      up.Data.Name,
			Size:      up.Data.Size,
			CreatedAt: up.Data.CreatedAt,
			Gateway:   gwURL,
			TokenURI:  tokenURI,
			Tx: TxRequest{
				From:    sender,
				To:      nftAddr.Hex(),
				Data:    "0x" + hex.EncodeToString(data),
				Value:   "0x0",
				ChainID: chainID,
			},
			Approve: ApprovePlan{
				BridgeAddr: bridgeAddr,
				Network:    info.Network,
			},
			Transfer: TransferPlan{
				BridgeAddr:      bridgeAddr,
				OwnerAddressInB: ownerB,
				Network:         info.Network,
			},
		})
	} else {
		fileHeader, err := c.FormFile("payload")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing payload file"})
			return
		}

		f, err := fileHeader.Open()
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "cannot open payload"})
			return
		}
		defer f.Close()

		payloadBytes, err := ioReadAllLimit(f, 25<<20) // 25MB
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// 1) достаем public key получателя из contacts текущего юзера
		info, err := h.Contacts.GetContactKeyInfo(
			c.Request.Context(),
			strings.ToLower(sender),
			strings.ToLower(recipient),
		)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				c.JSON(http.StatusNotFound, gin.H{"error": "recipient public key not found in contacts"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		netKey := strings.ToLower(strings.TrimSpace(info.Network))
		bridgeAddr, ok := h.Cfg.BridgeByNetwork[netKey]
		if !ok {
			c.JSON(400, gin.H{"error": "bridge is not configured for network: " + info.Network})
			return
		}

		pubECDSA, err := parsePubKey(info.PubKey)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "bad recipient public key: " + err.Error()})
			return
		}

		// 2) шифруем bytes получателя

		cipher, err := cryptoenc.EncryptBytes(pubECDSA, payloadBytes, fileHeader.Filename)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// 3) загружаем в IPFS (Pinata)
		pin, err := ipfs.NewFromEnv()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		name := fileHeader.Filename
		if name == "" {
			name = "document"
		}
		nameEnc := name + ".enc"

		up, err := pin.UploadBytes(nameEnc, cipher)
		if err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
			return
		}

		gateway := strings.TrimSpace(os.Getenv("PINATA_GATEWAY"))
		gwURL := ""
		if gateway != "" {
			gwURL = "https://" + gateway + "/ipfs/" + up.Data.Cid
		}

		// 4) CID -> tokenURI
		//    Обычно для NFT используют ipfs://CID
		tokenURI := "ipfs://" + up.Data.Cid
		if nameEnc != "" {
			tokenURI = tokenURI + "?name=" + url.QueryEscape(nameEnc)
		}

		// encLink := encryptionAbe.EncryptLink(tokenURI, dept, role)
		// tokenURI, err = encryptionAbe.MarshalEncryptedDataToString(encLink)
		// tokenURI = tokenURI + "?name=" + url.QueryEscape(nameEnc)
		// if err != nil {
		// 	log.Println("error encrypting tokenURI: ", err)
		// }

		// 5) Формируем calldata для createToken(owner, tokenURI)
		nftAddrStr := strings.TrimSpace(os.Getenv("NFT_ADDR"))
		if !common.IsHexAddress(nftAddrStr) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "NFT_ADDR env is missing or invalid"})
			return
		}
		nftAddr := common.HexToAddress(nftAddrStr)

		parsedABI, err := abi.JSON(strings.NewReader(nftABI))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "nft abi parse failed: " + err.Error()})
			return
		}

		data, err := parsedABI.Pack("createToken", tokenURI)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "abi pack failed: " + err.Error()})
			return
		}

		ownerB := strings.ToLower(strings.TrimSpace(recipient))

		// 6) Возвращаем tx request для MetaMask
		c.JSON(http.StatusOK, SendFileResp{
			Cid:       up.Data.Cid,
			Name:      up.Data.Name,
			Size:      up.Data.Size,
			CreatedAt: up.Data.CreatedAt,
			Gateway:   gwURL,
			TokenURI:  tokenURI,
			Tx: TxRequest{
				From:    sender,
				To:      nftAddr.Hex(),
				Data:    "0x" + hex.EncodeToString(data),
				Value:   "0x0",
				ChainID: chainID,
			},
			Approve: ApprovePlan{
				BridgeAddr: bridgeAddr,
				Network:    info.Network,
			},
			Transfer: TransferPlan{
				BridgeAddr:      bridgeAddr,
				OwnerAddressInB: ownerB,
				Network:         info.Network,
			},
		})
	}

}

// --- parsePubKey оставь как было ---
func parsePubKey(s string) (*ecdsa.PublicKey, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")

	if b, err := hex.DecodeString(s); err == nil && len(b) > 0 {
		pub, err := crypto.UnmarshalPubkey(b)
		if err == nil {
			return pub, nil
		}
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) > 0 {
		pub, err := crypto.UnmarshalPubkey(b)
		if err == nil {
			return pub, nil
		}
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil && len(b) > 0 {
		pub, err := crypto.UnmarshalPubkey(b)
		if err == nil {
			return pub, nil
		}
	}
	return nil, errors.New("cannot decode pubkey (expected hex or base64)")
}
