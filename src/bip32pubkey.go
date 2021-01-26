package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"

	"github.com/btcsuite/btcutil/base58"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
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
		data = append(data, me.KeyComp()...)
		data = append(data, indexBytes...)
		dataHashBytes := HMACSHA512(data, me.chainCode)

		keyBytes := secp256k1.CompressPubkey(
			secp256k1.S256().ScalarBaseMult(dataHashBytes[:32]),
		)

		// 可能需要添加一个key字段了
		// 或者搜索(*ecdsa.PublicKey 如何根据字节生成公钥
		testKey := addPubKeyBytes(keyBytes, me.KeyComp())
		fmt.Println(testKey)

		rst := BIP32NewPubKey(
			me.depth+1,
			RipeMD160(Sha256(me.KeyComp()))[:4],
			indexBytes,
			dataHashBytes[32:],
			nil,
		)
		return rst
	}
	panic("公钥不能生成强化密钥")
}

// addPubKeyBytes 私钥字节相加
func addPubKeyBytes(key1 []byte, key2 []byte) []byte {
	x1, y1 := secp256k1.DecompressPubkey(key1)
	x2, y2 := secp256k1.DecompressPubkey(key2)
	return secp256k1.CompressPubkey(secp256k1.S256().Add(x1, y1, x2, y2))
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
