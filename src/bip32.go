package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"

	"github.com/btcsuite/btcutil/base58"
)

// BIP32Key bip32标准的key结构
type BIP32Key struct {
	version     []byte
	depth       byte
	fingerPrint []byte
	childNumber []byte
	chainCode   []byte
	key         []byte
	isPrivate   bool
}

// Serialize s
func (me *BIP32Key) Serialize() []byte {
	buf := new(bytes.Buffer)
	buf.Write(me.version)
	buf.WriteByte(me.depth)
	buf.Write(me.fingerPrint)
	buf.Write(me.childNumber)
	buf.Write(me.chainCode)
	if me.isPrivate {
		buf.WriteByte(0x00)
	}
	buf.Write(me.key)
	rst := buf.Bytes()
	hash1 := sha256.Sum256(rst)
	hash2 := sha256.Sum256(hash1[:])
	rst = append(rst, hash2[:4]...)
	return rst
}

// SerializeBase58 s
func (me *BIP32Key) SerializeBase58() string {
	return base58.Encode(me.Serialize())
}

// NewRootPriKey 构造函数
func NewRootPriKey(seed []byte) *BIP32Key {
	rst := &BIP32Key{
		isPrivate: true,
	}
	h := hmac.New(sha512.New, []byte("Bitcoin seed"))
	h.Write(seed)
	hrst := h.Sum(nil)
	rst.version = []byte{0x04, 0x88, 0xad, 0xe4}
	rst.depth = 0x00
	rst.fingerPrint = []byte{0x00, 0x00, 0x00, 0x00}
	rst.childNumber = []byte{0x00, 0x00, 0x00, 0x00}
	rst.chainCode = hrst[32:]
	rst.key = hrst[:32]
	return rst
}
