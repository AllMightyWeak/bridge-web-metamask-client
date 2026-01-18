package eth

import "math/big"

func WeiToEthString(wei *big.Int) string {
	rat := new(big.Rat).SetInt(wei)
	den := new(big.Rat).SetInt(big.NewInt(1_000_000_000_000_000_000))
	rat.Quo(rat, den)
	return rat.FloatString(18)
}
