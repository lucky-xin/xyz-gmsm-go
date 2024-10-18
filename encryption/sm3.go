package encryption

import (
	"github.com/tjfoc/gmsm/sm3"
)

// EncodeToSM3 Encode To SM3
func EncodeToSM3(publicKeyHex string) []byte {
	h := sm3.New()
	h.Write([]byte(publicKeyHex))
	return h.Sum(nil)
}
