package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"math/big"

	"github.com/btcsuite/btcutil/base58"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
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

func uint32Bytes(num uint32) []byte {
	rst := make([]byte, 4)
	binary.BigEndian.PutUint32(rst, num)
	return rst
}

// ChildKey s
func (me *BIP32PriKey) ChildKey(index uint32) IBIP32Key {
	// 计算出index的uint32大端字节
	indexBytes := uint32Bytes(index)
	// 计算密钥data
	data := []byte{}
	if IsHardenedKeyIndex(index) {
		data = append(data, 0x00)
		data = append(data, me.key...)
	} else {
		data = append(data, me.BIP32PublicKey().KeyComp()...)
	}
	data = append(data, indexBytes...)
	dataHashBytes := HMACSHA512(data, me.chainCode)
	// 生成子私钥
	return BIP32NewPriKey(
		me.depth+1,
		RipeMD160(Sha256(me.BIP32PublicKey().KeyComp()))[:4],
		indexBytes,
		dataHashBytes[32:],
		addPriKeyBytes(dataHashBytes[:32], me.key),
	)
}

// addPriKeyBytes 私钥字节相加
func addPriKeyBytes(key1 []byte, key2 []byte) []byte {
	var key1Int big.Int
	var key2Int big.Int
	key1Int.SetBytes(key1)
	key2Int.SetBytes(key2)
	key1Int.Add(&key1Int, &key2Int)
	// curve是它自己实现的曲线，名为KoblitzCurve
	// 原来就是S256啊
	key1Int.Mod(&key1Int, secp256k1.S256().Params().N)
	rst := key1Int.Bytes()
	if len(rst) < 32 {
		extra := make([]byte, 32-len(rst))
		rst = append(extra, rst...)
	}
	return rst
}

// BIP32NewPriKey 构造函数
func BIP32NewPriKey(
	depth byte,
	fingerPrint []byte,
	childNumber []byte,
	chainCode []byte,
	key []byte,
) *BIP32PriKey {
	rst := &BIP32PriKey{}
	rst.BIP32KeyCom.version = []byte{0x04, 0x88, 0xad, 0xe4}
	rst.BIP32KeyCom.depth = depth
	rst.BIP32KeyCom.fingerPrint = fingerPrint
	rst.BIP32KeyCom.childNumber = childNumber
	rst.BIP32KeyCom.chainCode = chainCode
	rst.BIP32KeyCom.me = rst
	rst.key = key
	// 利用以太坊的库计算出ecdsa.PrivateKey
	priKey, err := crypto.ToECDSA(rst.key)
	if err != nil {
		panic(err)
	}
	rst.PrivateKey = priKey
	return rst
}

// BIP32NewRootPriKey 构造函数，构造BIP32根私钥
func BIP32NewRootPriKey(seed []byte) *BIP32PriKey {
	// HMACSHA512计算种子的hash
	hrst := HMACSHA512(seed, []byte("Bitcoin seed"))
	return BIP32NewPriKey(
		0x00,
		[]byte{0x00, 0x00, 0x00, 0x00},
		[]byte{0x00, 0x00, 0x00, 0x00},
		hrst[32:],
		hrst[:32],
	)
}
