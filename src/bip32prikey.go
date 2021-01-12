package main

import (
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha512"

	"github.com/ethereum/go-ethereum/crypto"
)

// BIP32PriKey BIP32私钥
type BIP32PriKey struct {
	BIP32KeyCom
}

// PublicKey 获取公钥
func (me *BIP32PriKey) PublicKey() *BIP32PubKey {
	rst := &BIP32PubKey{}
	rst.BIP32KeyCom.version = []byte{0x04, 0x88, 0xb2, 0x1e}
	rst.BIP32KeyCom.depth = me.depth
	rst.BIP32KeyCom.fingerPrint = me.fingerPrint
	rst.BIP32KeyCom.childNumber = me.childNumber
	rst.BIP32KeyCom.chainCode = me.chainCode

	// 椭圆曲线加密
	priKey, err := crypto.ToECDSA(me.key)
	if err != nil {
		panic(err)
	}
	pubKey := priKey.Public().(*ecdsa.PublicKey)
	pubKeyBytes := crypto.FromECDSAPub(pubKey)[1:]

	rst.BIP32KeyCom.key = append([]byte{0x03}, pubKeyBytes[:32]...)
	rst.BIP32KeyCom.me = rst
	return rst
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
