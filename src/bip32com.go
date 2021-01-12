package main

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
