package main

import (
	"crypto/ecdsa"
)

// BIP32PubKey BIP32公钥
type BIP32PubKey struct {
	BIP32KeyCom
	*ecdsa.PublicKey
}
