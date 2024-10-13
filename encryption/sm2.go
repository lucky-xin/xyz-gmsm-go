package encryption

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/tjfoc/gmsm/sm2"
	"math/big"
)

type SM2Encryption struct {
	publicKey  *sm2.PublicKey
	privateKey *sm2.PrivateKey
}

// NewSM2Encryption
// privateKeyHex 私钥16进制字符串
// publicKeyHex 公钥16进制字符串
func NewSM2Encryption(publicKeyHex, privateKeyHex string) (sm2e *SM2Encryption, err error) {
	publicKey, err := DecodePublicKey(publicKeyHex)
	if err != nil {
		return nil, err
	}
	privateKey, err := DecodePrivateKey(privateKeyHex, publicKeyHex)
	if err != nil {
		return nil, err
	}
	sm2e = &SM2Encryption{publicKey: publicKey, privateKey: privateKey}
	return
}

// DecodePublicKey 公钥字符串还原为 sm2.PublicKey 对象(与java中org.bouncycastle.crypto生成的公私钥完全互通使用)
// publicKeyHex: 公钥16进制字符串
func DecodePublicKey(publicKeyHex string) (*sm2.PublicKey, error) {
	publicKeyBytes, err := hex.DecodeString(publicKeyHex)
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

// DecodePrivateKey 将私钥字符串反序列化转为私钥对象
// 私钥还原为 sm2.PrivateKey对象(与java中org.bouncycastle.crypto生成的公私钥完全互通使用)
// privateKeyHex 私钥16进制字符串
// publicKeyHex 公钥16进制字符串
func DecodePrivateKey(privateKeyHex, publicKeyHex string) (*sm2.PrivateKey, error) {
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return nil, err
	}
	publicKey, err := DecodePublicKey(publicKeyHex)
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
// ciphertext 待解密密文字符串
// mode 加密模式:0=C1C3C2,1=C1C2C3
func (enc *SM2Encryption) Decrypt(ciphertext []byte, mode int) ([]byte, error) {
	return sm2.Decrypt(enc.privateKey, ciphertext, mode)
}

// DecryptHex 使用私钥对象解密密Hex文字符串
// ciphertext 待解密密文字符串
// mode 加密模式:0=C1C3C2,1=C1C2C3
// obj 解码对象
func (enc *SM2Encryption) DecryptHex(ciphertext string, mode int) ([]byte, error) {
	decodeByes, err := hex.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}
	return sm2.Decrypt(enc.privateKey, decodeByes, mode)
}

// DecryptBase64 使用私钥对象解密密Base64文字符串
// ciphertext 待解密密文字符串
// mode 加密模式:0=C1C3C2,1=C1C2C3
// obj 解码对象
func (enc *SM2Encryption) DecryptBase64(ciphertext string, mode int) ([]byte, error) {
	decodeByes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}
	return sm2.Decrypt(enc.privateKey, decodeByes, mode)
}

// DecryptObject 使用私钥对象解密密文字符串
// ciphertext 待解密密文字符串
// mode 加密模式:0=C1C3C2,1=C1C2C3
// obj 解码对象
func (enc *SM2Encryption) DecryptObject(ciphertext string, mode int, obj any) error {
	decodeString, err := hex.DecodeString(ciphertext)
	if err != nil {
		return err
	}
	decrypt, err := sm2.Decrypt(enc.privateKey, decodeString, mode)
	if err != nil {
		return err
	}
	return json.Unmarshal(decrypt, obj)
}

// Encrypt 加密
// plaintext 待加密明文字符串
// mode 加密模式:0=C1C3C2,1=C1C2C3
func (enc *SM2Encryption) Encrypt(plaintext string, mode int) ([]byte, error) {
	return sm2.Encrypt(enc.publicKey, []byte(plaintext), rand.Reader, mode)
}

// Encrypt2Hex 加密
// plaintext 待加密明文字符串
// mode 加密模式:0=C1C3C2,1=C1C2C3
func (enc *SM2Encryption) Encrypt2Hex(plaintext string, mode int) (string, error) {
	encryptedByts, err := enc.Encrypt(plaintext, mode)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(encryptedByts), nil
}

// Encrypt2Base64 加密
// plaintext 待加密明文字符串
// mode 加密模式:0=C1C3C2,1=C1C2C3
func (enc *SM2Encryption) Encrypt2Base64(plaintext string, mode int) (string, error) {
	encrypt, err := enc.Encrypt(plaintext, mode)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encrypt), err
}

// EncryptObject 加密JSON对象
// obj 待加密对象
// mode 加密模式:0=C1C3C2,1=C1C2C3
func (enc *SM2Encryption) EncryptObject(obj any, mode int) ([]byte, error) {
	marshal, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	return enc.Encrypt(string(marshal), mode)
}
