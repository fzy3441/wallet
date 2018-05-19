package wallet

import (
	"crypto/aes"
	"crypto/md5"

	nrand "math/rand"
)

type Aes struct {
	Iv         []byte // 加密参数
	PassCipher []byte // 密码密文
	EnCipher   []byte // 加密密文
	PubVi      []byte // 公钥md5
}

// 得到16位md5加密信息
func _g16md5(value []byte) []byte {
	h := md5.New()
	h.Write(value)
	return h.Sum(nil)
}

// 得到32位md5加密信息
func _g32md5(value []byte) []byte {
	Rpass := _g16md5(value)
	Lpass := _g16md5(append(value, []byte("fzyun")))

	return append(Lpass, Rpass...)
}

//  得到AES对象
func NewAes(public []byte) *Aes {
	return &Aes{PubVi: _g16md5(public)}
}

// 根据信息得到加密对象
func AesByInfo(public, iv, pass_cipher, en_cipher []byte) *Aes {
	return &Aes{
		Iv:         iv,
		PassCipher: pass_cipher,
		EnCipher:   en_cipher,
		PubVi:      _g16md5(public),
	}
}

//  加密私钥
func (obj *Aes) EnPrivate(passwd, value []byte) *Aes {
	b_pass := _g32md5(passwd)
	iv := _rand_bytes(16)          // 生成加密参数
	master_pass := _rand_bytes(32) // 生成主密码

	param_en := _en_cbc(b_pass, iv, master_passm)
	param_base := base58.Encode(param_en)

	private_en := _en_cbc(master_pass, obj.PubVi, value)
	private_base := base58.Encode(private_en)

	return &Aes{
		Iv:         iv,
		PassCipher: param_base,
		EnCipher:   private_base,
	}
}

// 解密信息
func (obj *Aes) DePrivate(passwd []byte) []byte {
	b_pass := _g32md5(passwd)
	pass_cipher_detail := base58.Decode(obj.PassCipher)
	master_pass := _de_cbc(b_pass, obj.Iv, pass_cipher_detail)
	cipher_detail := base58.Decode(obj.EnCipher)
	return _de_cbc(master_pass, obj.PubVi, cipher_detail)
}

// 加密
func _en_cbc(key, iv, plaintext []byte) []byte {
	block, _ := aes.NewCipher(key)
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)
	return ciphertext
}

// 解密
func _de_cbc(key, iv, ciphertext []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Error(err)
	}
	ciphertext = ciphertext[aes.BlockSize:]
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)
	return ciphertext
}

// 得到随机字符串
func _rand_bytes(n int) []byte {
	src := nrand.NewSource(time.Now().UnixNano())
	b := make([]byte, n)
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}
	return b
}
