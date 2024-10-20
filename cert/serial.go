package cert

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

func GenerateSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 64) // 2^64
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %s", err)
	}
	return serialNumber, nil
}
