package encryptionAbe

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"

	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/abe"
	"github.com/joho/godotenv"
)

// Структура открытого мастер ключа АВЕ
type FAMEPubKeyDTO struct {
	PartG2 [2]string `json:"part_g2"`
	PartGT [2]string `json:"part_gt"`
}

// Структура закрытого мастер ключа АВЕ
type FAMESecKeyDTO struct {
	PartInt [4]string `json:"part_int"`
	PartG1  [3]string `json:"part_g1"`
}

// Запись открытого мастер ключа АВЕ в .env
func writePubKeyABEToEnvFile(pubKey *abe.FAMEPubKey) bool {
	env, _ := godotenv.Read(".env")
	if env["PUBKEY_ADDED"] == "false" {
		pubKeyString, err := fAMEPubKeyToJSONString(pubKey)
		if err != nil {
			log.Println(err)
		}
		env["PUBKEY"] = pubKeyString
		env["PUBKEY_ADDED"] = "true"

		err = godotenv.Write(env, ".env")
		if err != nil {
			panic("Could not write to .env file")
		}
		return true
	}
	return false
}

// Чтение открытого мастер ключа АВЕ из .env
func readPubKeyABEFromEnvFile() (*abe.FAMEPubKey, error) {
	pubKeyString := os.Getenv("PUBKEY")
	return fAMEPubKeyFromJSONString(pubKeyString)
}

// Запись закрытого мастер ключа АВЕ в .env
func writeSecKeyABEToEnvFile(secKey *abe.FAMESecKey) bool {
	env, _ := godotenv.Read(".env")
	if env["SECKEY_ADDED"] == "false" {
		secKeyString, err := fAMESecKeyToJSONString(secKey)
		if err != nil {
			log.Println(err)
		}
		env["SECKEY"] = secKeyString
		env["SECKEY_ADDED"] = "true"

		err = godotenv.Write(env, ".env")
		if err != nil {
			panic("Could not write to .env file")
		}
		return true
	}
	return false
}

// Чтение закрытого мастер ключа АВЕ из .env
func readSecKeyABEFromEnvFile() (*abe.FAMESecKey, error) {
	secKeyString := os.Getenv("SECKEY")
	return fAMESecKeyFromJSONString(secKeyString)
}

// Преобразование открытого мастер ключа АВЕ в строку
func fAMEPubKeyToJSONString(pk *abe.FAMEPubKey) (string, error) {
	var dto FAMEPubKeyDTO

	for i := 0; i < 2; i++ {
		if pk.PartG2[i] == nil || pk.PartGT[i] == nil {
			return "", fmt.Errorf("nil key part at index %d", i)
		}
		dto.PartG2[i] = base64.RawStdEncoding.EncodeToString(pk.PartG2[i].Marshal())
		dto.PartGT[i] = base64.RawStdEncoding.EncodeToString(pk.PartGT[i].Marshal())
	}

	b, err := json.Marshal(dto)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Преобразование открытого мастер ключа АВЕ из строки в *abe.FAMEPubKey
func fAMEPubKeyFromJSONString(s string) (*abe.FAMEPubKey, error) {
	var dto FAMEPubKeyDTO
	if err := json.Unmarshal([]byte(s), &dto); err != nil {
		return nil, err
	}

	pk := &abe.FAMEPubKey{}
	for i := 0; i < 2; i++ {
		g2b, err := base64.RawStdEncoding.DecodeString(dto.PartG2[i])
		if err != nil {
			return nil, err
		}
		gtb, err := base64.RawStdEncoding.DecodeString(dto.PartGT[i])
		if err != nil {
			return nil, err
		}

		pk.PartG2[i] = new(bn256.G2) // <-- СМОТРИ НИЖЕ ПРО ТИП
		pk.PartGT[i] = new(bn256.GT) // <-- СМОТРИ НИЖЕ ПРО ТИП

		// В разных bn256 реализациях Unmarshal сигнатура отличается.
		// В cloudflare/bn256: Unmarshal([]byte) ([]byte, error) :contentReference[oaicite:3]{index=3}
		if _, err := pk.PartG2[i].Unmarshal(g2b); err != nil {
			return nil, err
		}
		if _, err := pk.PartGT[i].Unmarshal(gtb); err != nil {
			return nil, err
		}
	}

	return pk, nil
}

// Преобразование закрытого мастер ключа АВЕ в строку
func fAMESecKeyToJSONString(sk *abe.FAMESecKey) (string, error) {
	var dto FAMESecKeyDTO

	for i := 0; i < 4; i++ {
		if sk.PartInt[i] == nil {
			return "", fmt.Errorf("nil PartInt[%d]", i)
		}
		dto.PartInt[i] = base64.RawStdEncoding.EncodeToString(sk.PartInt[i].Bytes())
	}

	for i := 0; i < 3; i++ {
		if sk.PartG1[i] == nil {
			return "", fmt.Errorf("nil PartG1[%d]", i)
		}
		dto.PartG1[i] = base64.RawStdEncoding.EncodeToString(sk.PartG1[i].Marshal())
	}

	b, err := json.Marshal(dto)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Преобразование закрытого мастер ключа АВЕ из строки в *abe.FAMESecKey
func fAMESecKeyFromJSONString(s string) (*abe.FAMESecKey, error) {
	var dto FAMESecKeyDTO
	if err := json.Unmarshal([]byte(s), &dto); err != nil {
		return nil, err
	}

	sk := &abe.FAMESecKey{}

	// восстановление big.Int частей
	for i := 0; i < 4; i++ {
		b, err := base64.RawStdEncoding.DecodeString(dto.PartInt[i])
		if err != nil {
			return nil, fmt.Errorf("decode PartInt[%d]: %w", i, err)
		}
		sk.PartInt[i] = new(big.Int).SetBytes(b)
	}

	// восстановление G1 частей
	for i := 0; i < 3; i++ {
		b, err := base64.RawStdEncoding.DecodeString(dto.PartG1[i])
		if err != nil {
			return nil, fmt.Errorf("decode PartG1[%d]: %w", i, err)
		}
		sk.PartG1[i] = new(bn256.G1)
		if _, err := sk.PartG1[i].Unmarshal(b); err != nil {
			return nil, fmt.Errorf("unmarshal PartG1[%d]: %w", i, err)
		}
	}

	return sk, nil
}
