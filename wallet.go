package wallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

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
func createCurve() (*PrivateKey, *PublicKey) {
	curve := elliptic.P256()
	private, _ := ecdsa.GenerateKey(curve, rand.Reader)
	d := private.D.Bytes()
	b := make([]byte, 0, privKeyBytesLen)
	priv_complete := paddedAppend(privKeyBytesLen, b, d)
	pub_complete := append(private.PublicKey.X.Bytes(), private.PublicKey.Y.Bytes()...)

	public_key := &PubKey{Complete: pub_complete}
	private_key := &PrivKey{Ecdsa: private, Complete: priv_complete}

	return private_key, public_key
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

// 将短公角地址转换成Ecdsa公角对象
func pubEcdsaByShort(short []byte) *ecdsa.PublicKey {
	complete := base58.Decode(short)
	return PubByComplete(complete)
}

// 将完整公钥地址转换成公钥对象
func PubByComplete(complete []byte) *PubKey {
	return &Pubkey{Complete: complete}
}

// 将短公角地址转换成公角对象
func PubByShort(short []byte) *PubKey {
	complete := base58.Decode(short)
	return &Pubkey{Complete: complete}
}

// 短公钥信息
func (obj *PubKey) Short() []byte {
	return []byte(base58.Encode(obj.Complete))
}

// 生成钱包地址
func (obj *PubKey) Address() []byte {
	publicSHA256 := sha256.Sum256(obj.Complete)
	RIPEMD160Hasher := ripemd160.New()
	RIPEMD160Hasher.Write(publicSHA256[:])
	if err != nil {
		return nil
	}

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
	targetChecksum := checksum(append([]byte{version}, pubKeyHash...))
	return bytes.Compare(actualChecksum, targetChecksum) == 0
}

// 校难签名
func (obj *PubKey) Verify(sign string, data []byte) bool {
	public := pubEcdsaByComplete(obj.Complete)
	hash := sha256.Sum256(data)
	// 验签
	r := big.Int{}
	s := big.Int{}
	sigLen := len(sign)
	r.SetBytes(sign[:(sigLen / 2)])
	s.SetBytes(sign[(sigLen / 2):])

	return ecdsa.Verify(public, hash, &r, &s)
}

// 校验签名
func VerifyByComplete(complete []byte, sign string, data []byte) bool {
	public_key := &PubKey{Complete: complete}
	return public_key.Verify(sign, data)
}

// 短公钥校验
func VerifyByShort(short []byte, sign string, data []byte) bool {
	complete := base58.Decode(short)
	public_key := &PubKey{Complete: complete}
	return public_key.Verify(sign, data)
}

// 签名
func (obj *PrivKey) Sign(data []byte) (string, error) {
	hash := sha256.Sum256(data)

	r, s, err := ecdsa.Sign(rand.Reader, obj.Ecdsa, hash)
	if err != nil {
		return nil, err
	}

	byte_sing := append(r.Bytes(), s.Bytes()...)
	sign := base58.Encode(byte_sing)

	return sign, nil
}

// 将完整私钥地址还原私钥对象
func PrivByComplete(complete []byte) *PrivKey {
	// 转换为ecdsa
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = elliptic.P256()

	priv.D = new(big.Int).SetBytes(obj.AllKey)
	priv.PublicKey.X, priv.PublicKey.Y = priv.PublicKey.Curve.ScalarBaseMult(obj.AllKey)

	return &PrivKey{
		Ecdsa:    priv,
		Complete: complete,
	}
}

// 通过短私钥还原私钥对象
func PrivByShort(short []byte) *PrivKey {
	complete := base58.Decode(short)
	return PrivByComplete(complete)
}
