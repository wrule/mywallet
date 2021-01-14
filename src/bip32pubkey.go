package main

import (
	"crypto/ecdsa"
	"math/big"
)

// BIP32PubKey BIP32公钥
type BIP32PubKey struct {
	x *big.Int
	y *big.Int
	BIP32KeyCom
	*ecdsa.PublicKey
}

// X x坐标点
func (me *BIP32PubKey) X() *big.Int {
	return me.x
}

// Y y坐标点
func (me *BIP32PubKey) Y() *big.Int {
	return me.y
}
