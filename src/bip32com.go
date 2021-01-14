package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"

	"github.com/btcsuite/btcutil/base58"
)

// BIP32KeyCom BIP32钥匙共用实现
type BIP32KeyCom struct {
	version     []byte
	depth       byte
	fingerPrint []byte
	childNumber []byte
	chainCode   []byte
	key         []byte
	me          IBIP32Key
}

// Serialize 字节序列化
func (me *BIP32KeyCom) Serialize() []byte {
	buf := new(bytes.Buffer)
	buf.Write(me.version)
	buf.WriteByte(me.depth)
	buf.Write(me.fingerPrint)
	buf.Write(me.childNumber)
	buf.Write(me.chainCode)
	if _, ok := me.Me().(*BIP32PriKey); ok {
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
func (me *BIP32KeyCom) SerializeBase58() string {
	return base58.Encode(me.Serialize())
}

// Hex s
func (me *BIP32KeyCom) Hex() string {
	return hex.EncodeToString(me.key)
}

// Version s
func (me *BIP32KeyCom) Version() []byte {
	return me.version
}

// Depth s
func (me *BIP32KeyCom) Depth() byte {
	return me.depth
}

// FingerPrint s
func (me *BIP32KeyCom) FingerPrint() []byte {
	return me.fingerPrint
}

// ChildNumber s
func (me *BIP32KeyCom) ChildNumber() []byte {
	return me.childNumber
}

// ChainCode s
func (me *BIP32KeyCom) ChainCode() []byte {
	return me.chainCode
}

// Key s
func (me *BIP32KeyCom) Key() []byte {
	return me.key
}

// Me s
func (me *BIP32KeyCom) Me() IBIP32Key {
	return me.me
}
