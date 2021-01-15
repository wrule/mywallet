package main

import "encoding/hex"

// BIP32KeyCom BIP32钥匙共用实现
type BIP32KeyCom struct {
	version     []byte
	depth       byte
	fingerPrint []byte
	childNumber []byte
	chainCode   []byte
	me          IBIP32Key
}

// Hex 十六进制显示原始数据
func (me *BIP32KeyCom) Hex() string {
	return hex.EncodeToString(me.Me().Key())
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

// Me s
func (me *BIP32KeyCom) Me() IBIP32Key {
	return me.me
}
