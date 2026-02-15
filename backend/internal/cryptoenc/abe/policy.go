package encryptionAbe

import (
	"fmt"
	"log"
	"math"
	"strconv"

	"github.com/fentec-project/gofe/abe"
)

const (
	chief = iota + math.MaxInt - 4
	lawyer
	developer
	marketingSpecialist
)

const (
	legal = iota
	it
	accounting
)

// Генерация мастер ключей АВЕ
func GenMasterKeys() string {
	a := abe.NewFAME()
	pubKey, secKey, err := a.GenerateMasterKeys()
	if err != nil {
		log.Fatal("error generating ABE master keys: ", err)
	}
	pubRes := writePubKeyABEToEnvFile(pubKey)
	secRes := writeSecKeyABEToEnvFile(secKey)
	if pubRes && secRes {
		return "keys generated"
	}
	return "keys exist already"

}

// Генерация атрибутов
func generateAttributes(department, role int) ([]string, error) {
	switch department {
	case 0:
		switch role {
		case 0:
			return []string{
				strconv.Itoa(department),
				strconv.Itoa(chief),
				strconv.Itoa(lawyer),
			}, nil
		case 1:
			return []string{
				strconv.Itoa(department),
				strconv.Itoa(lawyer),
			}, nil
		default:
			return []string{}, fmt.Errorf("unknown policy")
		}
	case 1:
		switch role {
		case 0:
			return []string{
				strconv.Itoa(department),
				strconv.Itoa(chief),
				strconv.Itoa(developer),
			}, nil
		case 1:
			return []string{
				strconv.Itoa(department),
				strconv.Itoa(developer),
			}, nil
		default:
			return []string{}, fmt.Errorf("unknown policy")
		}
	case 2:
		switch role {
		case 0:
			return []string{
				strconv.Itoa(department),
				strconv.Itoa(chief),
				strconv.Itoa(marketingSpecialist),
			}, nil
		case 1:
			return []string{
				strconv.Itoa(department),
				strconv.Itoa(marketingSpecialist),
			}, nil
		default:
			return []string{}, fmt.Errorf("unknown policy")
		}
	default:
		return []string{}, fmt.Errorf("unknown policy")
	}
}

// Генерация атрибутных ключей
func GenerateAttributeKeys(department, role int) *abe.FAMEAttribKeys {
	gamma, err := generateAttributes(department, role)
	if err != nil {
		log.Fatal("error generating attributes: ", err)
	}
	fmt.Println()
	fmt.Println("Атрибуты")
	PrintPolicy(department, role)

	secKey, err := readSecKeyABEFromEnvFile()
	if err != nil {
		log.Fatal("error getting secret key from .env: ", err)
	}

	a := abe.NewFAME()
	keys, err := a.GenerateAttribKeys(gamma, secKey)
	if err != nil {
		log.Fatal("error generating attribute keys from .env: ", err)
	}

	return keys
}

// Генерация политики
func createPolicy(department, role int) (string, error) {
	policy := fmt.Sprintf("%d AND (", department)
	switch department {
	case 0:
		switch role {
		case 0:
			policy = fmt.Sprintf("%s%d AND %d", policy, chief, lawyer)
		case 1:
			policy = fmt.Sprintf("%s%d", policy, lawyer)
		default:
			return "", fmt.Errorf("unknown policy")
		}
	case 1:
		switch role {
		case 0:
			policy = fmt.Sprintf("%s%d AND %d", policy, chief, developer)
		case 1:
			policy = fmt.Sprintf("%s%d ", policy, developer)
		default:
			return "", fmt.Errorf("unknown policy")
		}
	case 2:
		switch role {
		case 0:
			policy = fmt.Sprintf("%s%d AND %d", policy, chief, marketingSpecialist)
		case 1:
			policy = fmt.Sprintf("%s%d", policy, marketingSpecialist)
		default:
			return "", fmt.Errorf("unknown policy")
		}
	}

	return policy + ")", nil
}
