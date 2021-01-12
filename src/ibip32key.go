package main

// IBIP32Key BIP32钥匙接口
type IBIP32Key interface {
	Version() []byte
	Depth() byte
	FingerPrint() []byte
	ChildNumber() []byte
	ChainCode() []byte
	Key() []byte
}
