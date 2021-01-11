package main

import (
	"crypto/hmac"
	"crypto/sha512"
)

// BIP32Key bip32标准的key结构
type BIP32Key struct {
	version     []byte
	depth       []byte
	fingerPrint []byte
	childNumber []byte
	chainCode   []byte
	key         []byte
	isPrivate   bool
}

// NewRootPriKey 构造函数
func NewRootPriKey() *BIP32Key {
	return nil
}

// BIP32GetRootPriKey 根据种子获取根私钥
func BIP32GetRootPriKey(seed []byte) {
	h := hmac.New(sha512.New, []byte("Bitcoin seed"))
	h.Write(seed)
	hrst := h.Sum(nil)
	keyBytes := hrst[:32]
	chainCodeBytes := hrst[32:]
}
