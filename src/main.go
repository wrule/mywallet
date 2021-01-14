package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"

	btcutil "github.com/FactomProject/btcutilecc"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tyler-smith/go-bip32"
)

func main() {
	bytes, err := hex.DecodeString("0c1e24e5917779d297e14d45f14e1a1a")
	if err != nil {
		panic(err)
	}
	fmt.Println(hex.EncodeToString(bytes))
	bip39 := NewBIP39ByFile("/home/gu/github/mywallet/bip39wordlist-en.txt")
	words := bip39.GenerateWords(bytes)
	fmt.Println(words)
	seed := BIP39GetSeed(words, "")
	fmt.Println(hex.EncodeToString(seed))

	rootPriKey, _ := bip32.NewMasterKey(seed)
	rootPubKey := rootPriKey.PublicKey()
	fmt.Println(rootPriKey.B58Serialize())
	fmt.Println(rootPubKey.B58Serialize())

	fmt.Println(hex.EncodeToString(rootPriKey.Key))

	myRootPriKey := BIP32NewRootPriKey(seed)
	fmt.Println(myRootPriKey.BIP32Base58())
	fmt.Println(myRootPriKey.Hex())
	// fmt.Println(myRootPriKey.BIP32PublicKey().SerializeBase58(), len(myRootPriKey.BIP32PublicKey().Key()))
	return

	// 测试代码
	curve := btcutil.Secp256k1()
	x, y := curve.ScalarBaseMult(myRootPriKey.Key())
	xBytes := x.Bytes()
	yBytes := y.Bytes()
	fmt.Println(hex.EncodeToString(xBytes), len(xBytes))
	fmt.Println(hex.EncodeToString(yBytes), len(yBytes))
	ePriKey, err := crypto.ToECDSA(myRootPriKey.Key())
	if err != nil {
		panic(err)
	}
	ePriKeyBytes := crypto.FromECDSA(ePriKey)
	fmt.Println(hex.EncodeToString(ePriKeyBytes))
	fmt.Println(hex.EncodeToString(myRootPriKey.Key()))
	ePubKey := ePriKey.Public().(*ecdsa.PublicKey)
	ePubKeyBytes := crypto.FromECDSAPub(ePubKey)[1:]
	fmt.Println(hex.EncodeToString(ePubKeyBytes))
}
