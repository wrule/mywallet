package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"

	"github.com/btcsuite/btcutil/base58"
	"github.com/ethereum/go-ethereum/crypto"
)

// BIP32PubKey BIP32公钥
type BIP32PubKey struct {
	BIP32KeyCom
	*ecdsa.PublicKey
}

// Key 原始公钥
func (me *BIP32PubKey) Key() []byte {
	return me.KeyUnComp()[1:]
}

// KeyComp 压缩的公钥
func (me *BIP32PubKey) KeyComp() []byte {
	return elliptic.MarshalCompressed(crypto.S256(), me.X, me.Y)
}

// KeyUnComp 未压缩的公钥
func (me *BIP32PubKey) KeyUnComp() []byte {
	return elliptic.Marshal(crypto.S256(), me.X, me.Y)
}

// BIP32Base58 s
func (me *BIP32PubKey) BIP32Base58() string {
	buf := new(bytes.Buffer)
	buf.Write(me.version)
	buf.WriteByte(me.depth)
	buf.Write(me.fingerPrint)
	buf.Write(me.childNumber)
	buf.Write(me.chainCode)
	buf.Write(me.KeyComp())
	rst := buf.Bytes()
	hash1 := sha256.Sum256(rst)
	hash2 := sha256.Sum256(hash1[:])
	rst = append(rst, hash2[:4]...)
	return base58.Encode(rst)
}

// ChildKey s
func (me *BIP32PubKey) ChildKey(index uint32) IBIP32Key {
	if IsHardenedKeyIndex(index) == false {
		// 计算出index的uint32大端字节
		indexBytes := uint32Bytes(index)
		// 计算密钥data
		data := []byte{}
		if IsHardenedKeyIndex(index) {
			data = append(data, 0x00)
			data = append(data, me.key...)
		} else {
			data = append(data, me.BIP32PublicKey().KeyComp()...)
		}
		data = append(data, indexBytes...)
		dataHashBytes := HMACSHA512(data, me.chainCode)
	} else {
		panic("公钥不能生成强化密钥")
	}
	return nil
}

// BIP32NewPubKey 构造函数
func BIP32NewPubKey(
	depth byte,
	fingerPrint []byte,
	childNumber []byte,
	chainCode []byte,
	PublicKey *ecdsa.PublicKey,
) *BIP32PubKey {
	rst := &BIP32PubKey{}
	rst.BIP32KeyCom.version = []byte{0x04, 0x88, 0xb2, 0x1e}
	rst.BIP32KeyCom.depth = depth
	rst.BIP32KeyCom.fingerPrint = fingerPrint
	rst.BIP32KeyCom.childNumber = childNumber
	rst.BIP32KeyCom.chainCode = chainCode
	rst.BIP32KeyCom.me = rst
	rst.PublicKey = PublicKey
	return rst
}
