package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcutil/base58"
	"github.com/ethereum/go-ethereum/crypto"
)

// BIP32PriKey BIP32私钥
type BIP32PriKey struct {
	key []byte
	BIP32KeyCom
	*ecdsa.PrivateKey
}

// Key s
func (me *BIP32PriKey) Key() []byte {
	return me.key
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

// BIP32PublicKey 获取BIP32公钥
func (me *BIP32PriKey) BIP32PublicKey() *BIP32PubKey {
	rst := &BIP32PubKey{}
	rst.BIP32KeyCom.version = []byte{0x04, 0x88, 0xb2, 0x1e}
	rst.BIP32KeyCom.depth = me.depth
	rst.BIP32KeyCom.fingerPrint = me.fingerPrint
	rst.BIP32KeyCom.childNumber = me.childNumber
	rst.BIP32KeyCom.chainCode = me.chainCode
	rst.PublicKey = me.PrivateKey.Public().(*ecdsa.PublicKey)
	rst.BIP32KeyCom.me = rst
	return rst
}

// ChildKey s
func (me *BIP32PriKey) ChildKey(index uint32) IBIP32Key {
	indexBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(indexBytes, index)
	data := []byte{}
	// 如果是强化密钥
	if IsHardenedKeyIndex(index) {
		data = append([]byte{0x00}, me.key...)
	} else {
		data = append(data, me.BIP32PublicKey().KeyComp()...)
	}
	data = append(data, indexBytes...)
	dataHash := HMACSHA512(data, me.chainCode)
	fmt.Println(hex.EncodeToString(dataHash))
	rst := &BIP32PriKey{}
	rst.BIP32KeyCom.childNumber = indexBytes
	rst.BIP32KeyCom.depth = me.depth + 1
	rst.BIP32KeyCom.chainCode = dataHash[32:]
	return rst
}

// BIP32NewRootPriKey 构造函数，构造BIP32根私钥
func BIP32NewRootPriKey(seed []byte) *BIP32PriKey {
	rst := &BIP32PriKey{}
	// HMACSHA512计算种子的hash
	hrst := HMACSHA512(seed, []byte("Bitcoin seed"))
	// 填充根私钥匙初始化数据
	rst.BIP32KeyCom.version = []byte{0x04, 0x88, 0xad, 0xe4}
	rst.BIP32KeyCom.depth = 0x00
	rst.BIP32KeyCom.fingerPrint = []byte{0x00, 0x00, 0x00, 0x00}
	rst.BIP32KeyCom.childNumber = []byte{0x00, 0x00, 0x00, 0x00}
	rst.BIP32KeyCom.chainCode = hrst[32:]
	rst.BIP32KeyCom.me = rst
	// 需要校验？
	rst.key = hrst[:32]
	// 利用以太坊的库计算出ecdsa.PrivateKey
	priKey, err := crypto.ToECDSA(rst.key)
	if err != nil {
		panic(err)
	}
	rst.PrivateKey = priKey
	return rst
}
