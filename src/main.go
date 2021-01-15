package main

import (
	"encoding/hex"
	"fmt"

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

	childPriKey1, err := rootPriKey.NewChildKey(0)
	if err != nil {
		panic(err)
	}
	fmt.Println(childPriKey1.B58Serialize())
	childPubKey1, err := rootPubKey.NewChildKey(0)
	if err != nil {
		panic(err)
	}
	fmt.Println(childPubKey1.B58Serialize())

	// myRootPriKey := BIP32NewRootPriKey(seed)
	// fmt.Println(myRootPriKey.Hex())
	// fmt.Println(myRootPriKey.BIP32Base58())
	// myRootPubKey := myRootPriKey.BIP32PublicKey()
	// fmt.Println(myRootPubKey.Hex())
	// fmt.Println(myRootPubKey.BIP32Base58())
}
