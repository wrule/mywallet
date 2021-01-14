package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"

	"github.com/btcsuite/btcutil/base58"
	"github.com/ethereum/go-ethereum/crypto"
)

// BIP32PriKey BIP32私钥
type BIP32PriKey struct {
	BIP32KeyCom
	*ecdsa.PrivateKey
}

// BIP32PublicKey 获取BIP32公钥
func (me *BIP32PriKey) BIP32PublicKey() *BIP32PubKey {
	rst := &BIP32PubKey{}
	rst.BIP32KeyCom.version = []byte{0x04, 0x88, 0xb2, 0x1e}
	rst.BIP32KeyCom.depth = me.depth
	rst.BIP32KeyCom.fingerPrint = me.fingerPrint
	rst.BIP32KeyCom.childNumber = me.childNumber
	rst.BIP32KeyCom.chainCode = me.chainCode
	rst.PublicKey = me.PrivateKey.Public().(*ecdsa.PublicKey)
	rst.BIP32KeyCom.key = elliptic.Marshal(crypto.S256(), rst.PublicKey.X, rst.PublicKey.Y)
	rst.BIP32KeyCom.me = rst
	return rst
}

// BIP32NewRootPriKey 构造函数，构造根私钥
func BIP32NewRootPriKey(seed []byte) *BIP32PriKey {
	rst := &BIP32PriKey{}
	// HMACSHA256计算种子的hash
	h := hmac.New(sha512.New, []byte("Bitcoin seed"))
	_, err := h.Write(seed)
	if err != nil {
		panic(err)
	}
	hrst := h.Sum(nil)
	// 填充根私钥匙初始化数据
	rst.BIP32KeyCom.version = []byte{0x04, 0x88, 0xad, 0xe4}
	rst.BIP32KeyCom.depth = 0x00
	rst.BIP32KeyCom.fingerPrint = []byte{0x00, 0x00, 0x00, 0x00}
	rst.BIP32KeyCom.childNumber = []byte{0x00, 0x00, 0x00, 0x00}
	rst.BIP32KeyCom.chainCode = hrst[32:]
	// 需要校验？
	rst.BIP32KeyCom.key = hrst[:32]
	rst.BIP32KeyCom.me = rst
	// 利用以太坊的库计算出ecdsa.PrivateKey
	rst.PrivateKey, err = crypto.ToECDSA(rst.BIP32KeyCom.key)
	if err != nil {
		panic(err)
	}
	return rst
}

// BIP32Base58 s
func (me *BIP32PriKey) BIP32Base58() string {
	buf := new(bytes.Buffer)
	buf.Write(me.version)
	buf.WriteByte(me.depth)
	buf.Write(me.fingerPrint)
	buf.Write(me.childNumber)
	buf.Write(me.chainCode)
	buf.WriteByte(0x00)
	buf.Write(me.key)
	rst := buf.Bytes()
	hash1 := sha256.Sum256(rst)
	hash2 := sha256.Sum256(hash1[:])
	rst = append(rst, hash2[:4]...)
	return base58.Encode(rst)
}
