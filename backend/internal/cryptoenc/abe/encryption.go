package encryptionAbe

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"strconv"

	"github.com/ddulesov/gogost/gost3412128"
	"github.com/ddulesov/gogost/mgm"
	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/abe"
	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/sample"
)

type EncryptedData struct {
	Cipher *FAMECipher
	Policy string
}

type FAMECipher struct {
	Ct0     [3]*bn256.G2
	Ct      [][3]*bn256.G1
	CtPrime *bn256.GT
	Msp     *abe.MSP

	SymEnc []byte
	Nonce  []byte
}

type KuznichikFAME struct {
	*abe.FAME
}

// Зашифрование данных
func EncryptLink(link string, department, role int) EncryptedData {
	policy, err := createPolicy(department, role)
	if err != nil {
		log.Fatal("error creating policy: ", err)
	}

	fmt.Println("Политика")
	PrintPolicy(department, role)

	msp, err := abe.BooleanToMSP(policy, true)
	if err != nil {
		log.Fatal("error getting msp policy: ", err)
	}

	pubKey, err := readPubKeyABEFromEnvFile()
	if err != nil {
		log.Fatal("error getting public key from .env: ", err)
	}

	a := abe.NewFAME()
	b := KuznichikFAME{FAME: a}
	cipher, err := b.Encrypt(link, msp, pubKey)
	if err != nil {
		log.Fatal("error encrypting data: ", err)
	}

	return EncryptedData{Cipher: cipher, Policy: policy}
}

func (a *KuznichikFAME) Encrypt(msg string, msp *abe.MSP, pk *abe.FAMEPubKey) (*FAMECipher, error) {
	if len(msp.Mat) == 0 || len(msp.Mat[0]) == 0 {
		return nil, fmt.Errorf("empty msp matrix")
	}

	attrib := make(map[string]bool)
	for _, i := range msp.RowToAttrib {
		if attrib[i] {
			return nil, fmt.Errorf("some attributes correspond to multiple rows of the MSP struct, scheme not secure")
		}
		attrib[i] = true
	}

	_, keyGt, err := bn256.RandomGT(rand.Reader)
	if err != nil {
		return nil, err
	}

	kuzKey, err := deriveKuzKeyFromGT(keyGt.Marshal())
	if err != nil {
		return nil, err
	}

	aad := aadFromMSP(msp)

	msgByte := []byte(msg)
	symEnc, nonce, err := encryptKuznechik(msgByte, kuzKey, aad)
	if err != nil {
		return nil, err
	}

	sampler := sample.NewUniform(a.P)
	s, err := data.NewRandomVector(2, sampler)
	if err != nil {
		return nil, err
	}

	ct0 := [3]*bn256.G2{
		new(bn256.G2).ScalarMult(pk.PartG2[0], s[0]),
		new(bn256.G2).ScalarMult(pk.PartG2[1], s[1]),
		new(bn256.G2).ScalarBaseMult(new(big.Int).Add(s[0], s[1])),
	}

	ct := make([][3]*bn256.G1, len(msp.Mat))
	for i := 0; i < len(msp.Mat); i++ {
		for l := 0; l < 3; l++ {
			hs1, err := bn256.HashG1(msp.RowToAttrib[i] + " " + strconv.Itoa(l) + " 0")
			if err != nil {
				return nil, err
			}
			hs1.ScalarMult(hs1, s[0])

			hs2, err := bn256.HashG1(msp.RowToAttrib[i] + " " + strconv.Itoa(l) + " 1")
			if err != nil {
				return nil, err
			}
			hs2.ScalarMult(hs2, s[1])

			ct[i][l] = new(bn256.G1).Add(hs1, hs2)

			for j := 0; j < len(msp.Mat[0]); j++ {
				hs1, err = bn256.HashG1("0 " + strconv.Itoa(j) + " " + strconv.Itoa(l) + " 0")
				if err != nil {
					return nil, err
				}
				hs1.ScalarMult(hs1, s[0])

				hs2, err = bn256.HashG1("0 " + strconv.Itoa(j) + " " + strconv.Itoa(l) + " 1")
				if err != nil {
					return nil, err
				}
				hs2.ScalarMult(hs2, s[1])

				hsToM := new(bn256.G1).Add(hs1, hs2)
				pow := new(big.Int).Set(msp.Mat[i][j])
				if pow.Sign() == -1 {
					pow.Neg(pow)
					hsToM.ScalarMult(hsToM, pow)
					hsToM.Neg(hsToM)
				} else {
					hsToM.ScalarMult(hsToM, pow)
				}
				ct[i][l].Add(ct[i][l], hsToM)
			}
		}
	}

	ctPrime := new(bn256.GT).ScalarMult(pk.PartGT[0], s[0])
	ctPrime.Add(ctPrime, new(bn256.GT).ScalarMult(pk.PartGT[1], s[1]))
	ctPrime.Add(ctPrime, keyGt)

	return &FAMECipher{
		Ct0:     ct0,
		Ct:      ct,
		CtPrime: ctPrime,
		Msp:     msp,
		SymEnc:  symEnc,
		Nonce:   nonce,
	}, nil
}

func encryptKuznechik(plaintext, key, aad []byte) ([]byte, []byte, error) {
	block := gost3412128.NewCipher(key)

	aead, err := mgm.NewMGM(block, 16)
	if err != nil {
		return nil, nil, err
	}

	nonce := mgmNonce(aead.NonceSize())
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	return ciphertext, nonce, nil
}

// Расшифрование данных
func DecryptLink(cipher *FAMECipher, attrKey *abe.FAMEAttribKeys) (string, error) {
	pubKey, err := readPubKeyABEFromEnvFile()
	if err != nil {
		return "", err
	}

	a := abe.NewFAME()
	b := KuznichikFAME{FAME: a}
	decoded, err := b.Decrypt(cipher, attrKey, pubKey)
	if err != nil {
		return "", err
	}

	return decoded, nil
}

func (a *KuznichikFAME) Decrypt(cipher *FAMECipher, key *abe.FAMEAttribKeys, pk *abe.FAMEPubKey) (string, error) {

	attribMap := make(map[string]bool)
	for k := range key.AttribToI {
		attribMap[k] = true
	}

	countAttrib := 0
	for i := 0; i < len(cipher.Msp.Mat); i++ {
		if attribMap[cipher.Msp.RowToAttrib[i]] {
			countAttrib++
		}
	}
	if countAttrib == 0 {
		return "", fmt.Errorf("provided key is not sufficient for decryption")
	}

	preMatForKey := make([]data.Vector, countAttrib)
	ctForKey := make([][3]*bn256.G1, countAttrib)
	rowToAttrib := make([]string, countAttrib)

	idx := 0
	for i := 0; i < len(cipher.Msp.Mat); i++ {
		if attribMap[cipher.Msp.RowToAttrib[i]] {
			preMatForKey[idx] = cipher.Msp.Mat[i]
			ctForKey[idx] = cipher.Ct[i]
			rowToAttrib[idx] = cipher.Msp.RowToAttrib[i]
			idx++
		}
	}

	matForKey, err := data.NewMatrix(preMatForKey)
	if err != nil || len(matForKey) == 0 {
		return "", fmt.Errorf("the provided cipher is faulty or key insufficient")
	}

	oneVec := data.NewConstantVector(len(matForKey[0]), big.NewInt(0))
	oneVec[0].SetInt64(1)

	alpha, err := data.GaussianEliminationSolver(matForKey.Transpose(), oneVec, a.P)
	if err != nil {
		return "", fmt.Errorf("provided key is not sufficient for decryption")
	}

	keyGt := new(bn256.GT).Set(cipher.CtPrime)

	ctProd := new([3]*bn256.G1)
	keyProd := new([3]*bn256.G1)

	for j := 0; j < 3; j++ {
		ctProd[j] = new(bn256.G1).ScalarBaseMult(big.NewInt(0))
		keyProd[j] = new(bn256.G1).ScalarBaseMult(big.NewInt(0))

		for i, e := range rowToAttrib {
			ctProd[j].Add(ctProd[j], new(bn256.G1).ScalarMult(ctForKey[i][j], alpha[i]))
			keyProd[j].Add(keyProd[j], new(bn256.G1).ScalarMult(key.K[key.AttribToI[e]][j], alpha[i]))
		}

		keyProd[j].Add(keyProd[j], key.KPrime[j])

		ctPairing := bn256.Pair(ctProd[j], key.K0[j])
		keyPairing := bn256.Pair(keyProd[j], cipher.Ct0[j])
		keyPairing.Neg(keyPairing)

		keyGt.Add(keyGt, ctPairing)
		keyGt.Add(keyGt, keyPairing)
	}

	kuzKe, err := deriveKuzKeyFromGT(keyGt.Marshal())
	if err != nil {
		return "", err
	}

	aad := aadFromMSP(cipher.Msp)

	pt, err := decryptKuznechik(kuzKe, cipher.SymEnc, cipher.Nonce, aad)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

func decryptKuznechik(key, ciphertext, nonce, aad []byte) ([]byte, error) {
	block := gost3412128.NewCipher(key)

	aead, err := mgm.NewMGM(block, 16)
	if err != nil {
		return nil, err
	}

	decrypted, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}
