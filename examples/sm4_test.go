package examples

import (
	"github.com/lucky-xin/xyz-gmsm-go/encryption"
	"testing"
)

func TestSm4(t *testing.T) {
	text := "国密算法SM4"
	key := "639e29c43d62713678897f3fd26b2e87"
	iv := "84eacb3e5a3c342c81efd57da905a948"
	sm2e, err := encryption.FromHex(key, iv)
	if err != nil {
		t.Error(err)
	}
	encryptText, err := sm2e.Encrypt2Hex(text)
	if err != nil {
		t.Error(err)
	}
	println(encryptText)
	decrypt, err := sm2e.DecryptHex(encryptText)
	if err != nil {
		t.Error(err)
	}
	println(string(decrypt))
	cipherText := "78b8ce5510f901d77bdf802c28b52d4dfbcaf9bdc2d4cff05ff691d7ea8776151d885592858386655b5ea32450c54d496dd59a92b9fc999c6b25253e26d252ac435178a002b8ea0f060ed20e066539ec"
	decrypt, err = sm2e.DecryptHex(cipherText)
	if err != nil {
		t.Error(err)
	}
	println(string(decrypt))

	encryptText, err = sm2e.Encrypt2Base64(text)
	if err != nil {
		t.Error(err)
	}
	println(encryptText)
	decrypt, err = sm2e.DecryptBase64(encryptText)
	if err != nil {
		t.Error(err)
	}
	println(string(decrypt))
}
