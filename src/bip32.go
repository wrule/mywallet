package main

import (
	"crypto/hmac"
	"crypto/sha512"
)

// BIP32NewRootPriKey 构造函数，构造根私钥
func BIP32NewRootPriKey(seed []byte) *BIP32PriKey {
	rst := &BIP32PriKey{}
	h := hmac.New(sha512.New, []byte("Bitcoin seed"))
	_, err := h.Write(seed)
	if err != nil {
		panic(err)
	}
	hrst := h.Sum(nil)
	rst.BIP32KeyCom.version = []byte{0x04, 0x88, 0xad, 0xe4}
	rst.BIP32KeyCom.depth = 0x00
	rst.BIP32KeyCom.fingerPrint = []byte{0x00, 0x00, 0x00, 0x00}
	rst.BIP32KeyCom.childNumber = []byte{0x00, 0x00, 0x00, 0x00}
	rst.BIP32KeyCom.chainCode = hrst[32:]
	// 需要校验？
	rst.BIP32KeyCom.key = hrst[:32]
	rst.BIP32KeyCom.me = rst
	return rst
}
