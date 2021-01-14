package main

import (
	"crypto/ecdsa"
)

// BIP32PubKey BIP32公钥
type BIP32PubKey struct {
	BIP32KeyCom
	*ecdsa.PublicKey
}

// BIP32Base58 s
func (me *BIP32PubKey) BIP32Base58() string {
	return ""
}
