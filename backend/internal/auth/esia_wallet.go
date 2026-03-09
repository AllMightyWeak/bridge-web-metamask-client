package auth

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testMM/backend/internal/util"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func walletLinkKey(esiaUserID string) string {
	return "walletlink:" + strings.TrimSpace(esiaUserID)
}

func (s *Service) InitWalletLink(esiaUserID, address string) (nonce string, message string, err error) {
	esiaUserID = strings.TrimSpace(esiaUserID)
	address = strings.TrimSpace(address)

	if esiaUserID == "" {
		return "", "", errors.New("esiaUserID is required")
	}
	if !common.IsHexAddress(address) {
		return "", "", errors.New("invalid ethereum address")
	}

	nonce, err = util.RandomBase64URL(16)
	if err != nil {
		return "", "", err
	}

	message = buildWalletLinkMessage(esiaUserID, address, nonce)

	exp := time.Now().Add(s.cfg.NonceTTL)
	s.nonces.Put(walletLinkKey(esiaUserID), NonceEntry{
		Nonce:     nonce,
		Domain:    strings.ToLower(common.HexToAddress(address).Hex()),
		ExpiresAt: exp,
	})

	return nonce, message, nil
}

func (s *Service) VerifyWalletLink(esiaUserID, address, message, signature string) error {
	esiaUserID = strings.TrimSpace(esiaUserID)
	address = strings.TrimSpace(address)

	if !common.IsHexAddress(address) {
		return errors.New("invalid ethereum address")
	}

	key := walletLinkKey(esiaUserID)
	entry, ok := s.nonces.Get(key)
	if !ok || time.Now().After(entry.ExpiresAt) {
		return errors.New("nonce expired or not found")
	}
	if entry.Domain != strings.ToLower(common.HexToAddress(address).Hex()) {
		return errors.New("address mismatch")
	}

	recovered, err := ecrecover(message, signature)
	if err != nil {
		return fmt.Errorf("ecrecover: %w", err)
	}
	if !strings.EqualFold(recovered.Hex(), common.HexToAddress(address).Hex()) {
		return errors.New("signature does not match address")
	}

	s.nonces.Delete(key)
	return nil
}

func buildWalletLinkMessage(esiaUserID, address, nonce string) string {
	return fmt.Sprintf(
		"Link wallet to ESIA account\nUser: %s\nAddress: %s\nNonce: %s",
		esiaUserID,
		common.HexToAddress(address).Hex(),
		nonce,
	)
}

func ecrecover(message, signature string) (common.Address, error) {
	sig, err := hex.DecodeString(strings.TrimPrefix(signature, "0x"))
	if err != nil {
		return common.Address{}, errors.New("invalid signature hex")
	}
	if len(sig) != 65 {
		return common.Address{}, errors.New("signature must be 65 bytes")
	}

	prefixed := fmt.Sprintf("\x19Ethereum Signed Message:\n%s%s",
		strconv.Itoa(len(message)), message)
	hash := crypto.Keccak256Hash([]byte(prefixed))

	sigCopy := make([]byte, 65)
	copy(sigCopy, sig)
	if sigCopy[64] >= 27 {
		sigCopy[64] -= 27
	}

	pubKey, err := crypto.SigToPub(hash.Bytes(), sigCopy)
	if err != nil {
		return common.Address{}, fmt.Errorf("SigToPub: %w", err)
	}

	return crypto.PubkeyToAddress(*pubKey), nil
}
