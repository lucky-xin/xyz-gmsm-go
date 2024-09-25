package encryption

import (
	"crypto/rand"
	"encoding/hex"
	"github.com/tjfoc/gmsm/sm2"
	"math/big"
	"strings"
)

type SM2Encryption struct {
	publicKey  *sm2.PublicKey
	privateKey *sm2.PrivateKey
}

func NewSM2Encryption(publicKeyStr, privateKeyStr string) (sm2e *SM2Encryption, err error) {
	publicKey, err := DecodePublicKey(publicKeyStr)
	if err != nil {
		return nil, err
	}
	privateKey, err := DecodePrivateKey(privateKeyStr, publicKeyStr)
	if err != nil {
		return nil, err
	}
	sm2e = &SM2Encryption{publicKey: publicKey, privateKey: privateKey}
	return
}

// DecodePublicKey 公钥字符串还原为 sm2.PublicKey 对象(与java中org.bouncycastle.crypto生成的公私钥完全互通使用)
func DecodePublicKey(publicKeyStr string) (*sm2.PublicKey, error) {
	publicKeyBytes, err := hex.DecodeString(publicKeyStr)
	if err != nil {
		return nil, err
	}
	// 提取 x 和 y 坐标字节切片
	curve := sm2.P256Sm2().Params()
	byteLen := (curve.BitSize + 7) / 8
	xBytes := publicKeyBytes[1 : byteLen+1]
	yBytes := publicKeyBytes[byteLen+1 : 2*byteLen+1]
	// 将字节切片转换为大整数
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	// 创建 sm2.PublicKey 对象
	publicKey := &sm2.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}
	return publicKey, nil
}

// 将私钥字符串反序列化转为私钥对象:
// DecodePrivateKey 私钥还原为 sm2.PrivateKey对象(与java中org.bouncycastle.crypto生成的公私钥完全互通使用)
func DecodePrivateKey(privateKeyStr, publicKeyStr string) (*sm2.PrivateKey, error) {
	privateKeyBytes, err := hex.DecodeString(privateKeyStr)
	if err != nil {
		return nil, err
	}
	publicKey, err := DecodePublicKey(publicKeyStr)
	if err != nil {
		return nil, err
	}
	// 将字节切片转换为大整数
	d := new(big.Int).SetBytes(privateKeyBytes)
	// 创建 sm2.PrivateKey 对象
	privateKey := &sm2.PrivateKey{
		PublicKey: *publicKey,
		D:         d,
	}
	return privateKey, nil
}

// Decrypt 使用私钥对象解密密文字符串
func (enc *SM2Encryption) Decrypt(cipherText string, mode int) (string, error) {
	decodeString, err := hex.DecodeString(cipherText)
	decrypt, err := sm2.Decrypt(enc.privateKey, decodeString, mode)
	if err != nil {
		return "", err
	}
	resultStr := string(decrypt)
	return resultStr, nil
}

// Encrypt  publicKeyStr 公钥字符串, text 待加密明文字符串
func (enc *SM2Encryption) Encrypt(text string, mode int) (string, error) {
	encryptStr, _ := sm2.Encrypt(enc.publicKey, []byte(text), rand.Reader, mode)
	encodeToString := hex.EncodeToString(encryptStr)
	return strings.ToUpper(encodeToString), nil
}
