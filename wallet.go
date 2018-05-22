package wallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"

	"bytes"
	"crypto/sha256"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/ripemd160"
)

// 钱包类型
type Wallet struct {
	PrivateKey *PrivKey
	PublicKey  *PubKey
}

// 私钥信息
type PrivKey struct {
	Ecdsa    *ecdsa.PrivateKey
	Complete []byte
}

// 公钥信息
type PubKey struct {
	Complete []byte // 完整公钥
	Address  []byte // 外部钱包地址
}

const version = byte(0x00)   // 当前钱包版本
const addressChecksumLen = 4 // 钱包地址长度
const privKeyBytesLen = 32   // 私钥长度

// 创建密钥
// func createCurve() (*PrivateKey, *PublicKey) {
func NewWallet() *Wallet {
	curve := elliptic.P256()
	private, _ := ecdsa.GenerateKey(curve, rand.Reader)
	d := private.D.Bytes()
	b := make([]byte, 0, privKeyBytesLen)
	priv_complete := paddedAppend(privKeyBytesLen, b, d)
	pub_complete := append(private.PublicKey.X.Bytes(), private.PublicKey.Y.Bytes()...)

	public_key := &PubKey{Complete: pub_complete}
	private_key := &PrivKey{Ecdsa: private, Complete: priv_complete}

	// return private_key, public_key
	wallet := &Wallet{
		PrivateKey: private_key,
		PublicKey:  public_key,
	}

	wallet.PublicKey._genAddress()
	return wallet
}

// 处理私钥编码
// 编码长度不足私钥长度时，加0补齐
func paddedAppend(size uint, dst, src []byte) []byte {
	for i := 0; i < int(size)-len(src); i++ {
		dst = append(dst, 0)
	}
	return append(dst, src...)
}

// 将完整公钥地址转换成Ecdsa公钥对象
func pubEcdsaByComplete(complete []byte) *ecdsa.PublicKey {
	curve := elliptic.P256()
	x := big.Int{}
	y := big.Int{}
	keyLen := len(complete)
	x.SetBytes(complete[:(keyLen / 2)])
	y.SetBytes(complete[(keyLen / 2):])
	public := ecdsa.PublicKey{curve, &x, &y}
	return &public
}

// // 将短公角地址转换成Ecdsa公角对象
// func pubEcdsaByShort(short []byte) *ecdsa.PublicKey {
// 	complete := base58.Decode(short)
// 	pubEcdsaByComplete(complete)
// 	// return PubByComplete(complete)

// }

// 将完整公钥地址转换成公钥对象
func (obj *Wallet) PubByComplete(complete []byte) {
	obj.PublicKey = &PubKey{Complete: complete}
	// return &PubKey{Complete: complete}
}

// 将短公角地址转换成公角对象
func (obj *Wallet) PubByShort(short string) {
	complete := base58.Decode(short)
	obj.PubByComplete(complete)
	// return &Pubkey{Complete: complete}
}

// 短公钥信息
func (obj *PubKey) Short() []byte {
	return []byte(base58.Encode(obj.Complete))
}

// 生成钱包地址
func (obj *PubKey) _genAddress() []byte {
	publicSHA256 := sha256.Sum256(obj.Complete)
	RIPEMD160Hasher := ripemd160.New()
	RIPEMD160Hasher.Write(publicSHA256[:])

	publicRIPEMD160 := RIPEMD160Hasher.Sum(nil)
	versionedPayload := append([]byte{version}, publicRIPEMD160...)
	firstSHA := sha256.Sum256(versionedPayload)
	secondSHA := sha256.Sum256(firstSHA[:])

	fullPayload := append(versionedPayload, secondSHA[:addressChecksumLen]...)

	obj.Address = []byte(base58.Encode(fullPayload))
	return obj.Address
}

// 检查地址是否有效
func (obj *PubKey) VerifyAddress(address string) bool {
	pubKeyHash := base58.Decode(address)
	actualChecksum := pubKeyHash[len(pubKeyHash)-addressChecksumLen:]
	version := pubKeyHash[0]
	pubKeyHash = pubKeyHash[1 : len(pubKeyHash)-addressChecksumLen]

	// 检查公钥长度
	firstSHA := sha256.Sum256(append([]byte{version}, pubKeyHash...))
	secondSHA := sha256.Sum256(firstSHA[:])
	targetChecksum := secondSHA[:addressChecksumLen]

	return bytes.Compare(actualChecksum, targetChecksum) == 0
}

// 校难签名
func (obj *PubKey) _verify(sign, data []byte) bool {
	public := pubEcdsaByComplete(obj.Complete)
	hash := sha256.Sum256(data)
	fmt.Println("hash2===>", hash)
	fmt.Println("sign2===>", sign)
	// 验签
	r := big.Int{}
	s := big.Int{}
	sigLen := len(sign)
	r.SetBytes(sign[:(sigLen / 2)])
	s.SetBytes(sign[(sigLen / 2):])

	return ecdsa.Verify(public, hash[:], &r, &s)
}

// 校验签名
func (obj *Wallet) Verify(sign string, data []byte) bool {
	// public_key := &PubKey{Complete: complete}
	byte_sing := base58.Decode(sign)
	return obj.PublicKey._verify([]byte(byte_sing), data)
	// return public_key.Verify(sign, data)
}

// // 短公钥校验
// func (obj *Wallet) VerifyByShort(short, sign string, data []byte) bool {
// 	complete := base58.Decode(short)
// 	// public_key := &PubKey{Complete: complete}
// 	return obj.PublicKey._verify([]byte(complete), data)
// 	// return public_key.Verify(sign, data)
// }

// 签名数据
func (obj *Wallet) Sign(data []byte) (string, error) {
	return obj.PrivateKey._sign(data)
}

// 签名
func (obj *PrivKey) _sign(data []byte) (string, error) {
	hash := sha256.Sum256(data)

	fmt.Println("hash1===>", hash)
	r, s, err := ecdsa.Sign(rand.Reader, obj.Ecdsa, hash[:])
	if err != nil {
		return "", err
	}

	byte_sing := append(r.Bytes(), s.Bytes()...)
	sign := base58.Encode(byte_sing)
	fmt.Println("sign1===>", byte_sing)
	fmt.Println("sign3===>", sign)
	return sign, nil
}

// 将完整私钥地址还原私钥对象
func (obj *Wallet) PrivByComplete(complete []byte) {
	// 转换为ecdsa
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = elliptic.P256()

	priv.D = new(big.Int).SetBytes(complete)
	priv.PublicKey.X, priv.PublicKey.Y = priv.PublicKey.Curve.ScalarBaseMult(complete)

	obj.PrivateKey = &PrivKey{
		Ecdsa:    priv,
		Complete: complete,
	}
}

// 通过短私钥还原私钥对象
func (obj *Wallet) PrivByShort(short string) {
	complete := base58.Decode(short)
	obj.PrivByComplete([]byte(complete))
}

// 加密私钥
func (obj *Wallet) EnKey(passwd string) *Aes {
	aes := NewAes(obj.PublicKey.Complete)
	aes.EnValue([]byte(passwd), obj.PrivateKey.Complete)
	return aes
}

func (obj *Wallet) DeKey(passwd string, iv []byte, pass_cipher, en_cipher string) bool {
	aes := AesByInfo(obj.PublicKey.Complete, iv, pass_cipher, en_cipher)
	str_priv, err := aes.DeValue([]byte(passwd))
	if err != nil {
		return false
	}

	obj.PrivByComplete(str_priv)

	return true
}
