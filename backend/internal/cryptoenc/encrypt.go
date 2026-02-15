package cryptoenc

import (
	"crypto/ecdsa"
	"crypto/rand"
	"log"
	"testMM/backend/internal/cryptoenc/gost"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
)

// EncryptMessage is taken from provided code (minimal adaptations).
func EncryptMessage(keyAny any, message []byte, filename string) []byte {
	var publicKeyECIES *ecies.PublicKey

	switch key := keyAny.(type) {
	case []byte:
		pub, err := crypto.UnmarshalPubkey(key)
		if err != nil {
			log.Println("err UnmarshalPubkey:", err)
			return nil
		}
		publicKeyECIES = ecies.ImportECDSAPublic(pub)
	case *ecies.PublicKey:
		publicKeyECIES = key
	case *ecdsa.PublicKey:
		publicKeyECIES = ecies.ImportECDSAPublic(key)
	default:
		log.Println("unsupported key type")
		return nil
	}

	ciphertext, err := gost.Encrypt(rand.Reader, publicKeyECIES, message, nil, nil, filename)
	if err != nil {
		log.Println("err Encrypt:", err)
		return nil
	}

	return ciphertext
}

func EncryptBytes(publicKeyECDSA *ecdsa.PublicKey, plaintext []byte, filename string) ([]byte, error) {
	ct := EncryptMessage(publicKeyECDSA, plaintext, filename)
	if ct == nil {
		return nil, ErrEncryptFailed
	}
	return ct, nil
}
