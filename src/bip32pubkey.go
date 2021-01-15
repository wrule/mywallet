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

// Key 原始公钥数据
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
