package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"

	"github.com/btcsuite/btcutil/base58"
)

// BIP32PriKey BIP32私钥
type BIP32PriKey struct {
	BIP32Key
}

// BIP32PubKey BIP32公钥
type BIP32PubKey struct {
	BIP32Key
}

// Serialize 字节序列化
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

// SerializeBase58 字节序列化后转为base58编码
func (me *BIP32Key) SerializeBase58() string {
	return base58.Encode(me.Serialize())
}

// BIP32NewRootPriKey 构造函数，构造根私钥
func BIP32NewRootPriKey(seed []byte) *BIP32PriKey {
	rst := &BIP32PriKey{}
	h := hmac.New(sha512.New, []byte("Bitcoin seed"))
	_, err := h.Write(seed)
	if err != nil {
		panic(err)
	}
	hrst := h.Sum(nil)
	rst.version = []byte{0x04, 0x88, 0xad, 0xe4}
	rst.depth = 0x00
	rst.fingerPrint = []byte{0x00, 0x00, 0x00, 0x00}
	rst.childNumber = []byte{0x00, 0x00, 0x00, 0x00}
	rst.chainCode = hrst[32:]
	// 需要校验？
	rst.key = hrst[:32]
	return rst
}
