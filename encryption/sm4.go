package encryption

import (
	"bytes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/tjfoc/gmsm/sm4"
)

type SM4 struct {
	key []byte
	iv  []byte
}

// NewSM4 新建SM4
func NewSM4(key, iv []byte) (sm2e *SM4, err error) {
	sm2e = &SM4{key: key, iv: iv}
	return
}

// FromHex 新建SM4
func FromHex(key, iv string) (sm2e *SM4, err error) {
	keyByts, err := hex.DecodeString(key)
	if err != nil {
		return nil, err
	}
	ivByts, err := hex.DecodeString(iv)
	if err != nil {
		return nil, err
	}

	sm2e = &SM4{key: keyByts, iv: ivByts}
	return
}

// FromBase64 新建SM4
func FromBase64(key, iv string) (sm2e *SM4, err error) {
	keyByts, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}
	ivByts, err := base64.StdEncoding.DecodeString(iv)
	if err != nil {
		return nil, err
	}

	sm2e = &SM4{key: keyByts, iv: ivByts}
	return
}

// Decrypt 使用私钥对象解密密文字符串
// ciphertext 待解密密文字符串
func (enc *SM4) Decrypt(ciphertext []byte) ([]byte, error) {
	block, err := sm4.NewCipher(enc.key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, enc.iv)
	blockMode.CryptBlocks(ciphertext, ciphertext)
	plainText := unpaddingLastGroup(ciphertext)
	return plainText, nil
}

// DecryptHex 使用私钥对象解密密Hex文字符串
// ciphertext 待解密密文字符串
func (enc *SM4) DecryptHex(ciphertext string) ([]byte, error) {
	decodeByes, err := hex.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}
	return enc.Decrypt(decodeByes)
}

// DecryptBase64 使用私钥对象解密密Base64文字符串
// ciphertext 待解密密文字符串
func (enc *SM4) DecryptBase64(ciphertext string) ([]byte, error) {
	decodeByes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}
	return enc.Decrypt(decodeByes)
}

// DecryptObject 使用私钥对象解密密文字符串
// ciphertext 待解密密文字符串
// obj 解码对象
func (enc *SM4) DecryptObject(ciphertext string, obj any) error {
	decodeByts, err := hex.DecodeString(ciphertext)
	if err != nil {
		return err
	}
	decrypt, err := enc.Decrypt(decodeByts)
	if err != nil {
		return err
	}
	return json.Unmarshal(decrypt, obj)
}

// Encrypt 加密
// plaintext 待加密明文字符串
func (enc *SM4) Encrypt(plaintext string) ([]byte, error) {
	block, err := sm4.NewCipher(enc.key)
	if err != nil {
		return nil, err
	}
	paddData := paddingLastGroup([]byte(plaintext), block.BlockSize())
	blokMode := cipher.NewCBCEncrypter(block, enc.iv)
	cipherText := make([]byte, len(paddData))
	blokMode.CryptBlocks(cipherText, paddData)
	return cipherText, nil
}

// Encrypt2Hex 加密
// plaintext 待加密明文字符串
func (enc *SM4) Encrypt2Hex(plaintext string) (string, error) {
	encryptedByts, err := enc.Encrypt(plaintext)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(encryptedByts), nil
}

// Encrypt2Base64 加密
// plaintext 待加密明文字符串
func (enc *SM4) Encrypt2Base64(plaintext string) (string, error) {
	encrypt, err := enc.Encrypt(plaintext)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encrypt), err
}

// EncryptObject 加密JSON对象
// obj 待加密对象
func (enc *SM4) EncryptObject(obj any) ([]byte, error) {
	marshal, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	return enc.Encrypt(string(marshal))
}

// 明文数据填充
func paddingLastGroup(plaintext []byte, blockSize int) []byte {
	//1.计算最后一个分组中明文后需要填充的字节数
	padNum := blockSize - len(plaintext)%blockSize
	//2.将字节数转换为byte类型
	char := []byte{byte(padNum)}
	//3.创建切片并初始化
	newPlain := bytes.Repeat(char, padNum)
	//4.将填充数据追加到原始数据后
	newText := append(plaintext, newPlain...)
	return newText
}

// 去掉明文后面的填充数据
func unpaddingLastGroup(plainText []byte) []byte {
	//1.拿到切片中的最后一个字节
	length := len(plainText)
	lastChar := plainText[length-1]
	//2.将最后一个数据转换为整数
	number := int(lastChar)
	return plainText[:length-number]
}
