package main

import (
	"encoding/hex"
	"fmt"

	"github.com/tyler-smith/go-bip32"
)

func main() {
	// 根据随机数生成种子
	bytes, err := hex.DecodeString("0c1e24e5917779d297e14d45f14e1a1a")
	if err != nil {
		panic(err)
	}
	bip39 := NewBIP39ByFile("/home/gu/github/mywallet/bip39wordlist-en.txt")
	words := bip39.GenerateWords(bytes)
	fmt.Println("助记词")
	fmt.Println(words)
	seed := BIP39GetSeed(words, "")
	fmt.Println("种子")
	fmt.Println(hex.EncodeToString(seed))

	fmt.Println()

	// 生成主私钥，主公钥，以及子密钥
	rootPriKey, _ := bip32.NewMasterKey(seed)
	rootPubKey := rootPriKey.PublicKey()
	fmt.Println(rootPriKey.B58Serialize())
	fmt.Println(rootPubKey.B58Serialize())
	childPriKey, err := rootPriKey.NewChildKey(0x80000001)
	if err != nil {
		panic(err)
	}
	fmt.Println(childPriKey.B58Serialize())
	childPubKey, err := rootPubKey.NewChildKey(0)
	if err != nil {
		panic(err)
	}
	fmt.Println(childPubKey.B58Serialize())

	fmt.Println()

	// s
	myRootPriKey := BIP32NewRootPriKey(seed)
	fmt.Println(myRootPriKey.BIP32Base58())
	myRootPubKey := myRootPriKey.BIP32PublicKey()
	fmt.Println(myRootPubKey.BIP32Base58())
	myChildPriKey := myRootPriKey.ChildKey(0x80000001)
	fmt.Println(myChildPriKey.BIP32Base58())
	myChildPubKey := myRootPubKey.ChildKey(0)
	fmt.Println(myChildPubKey.BIP32Base58())
}
