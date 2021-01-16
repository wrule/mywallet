package main

import (
	"encoding/hex"
	"fmt"
	"io"

	"github.com/tyler-smith/go-bip32"
	"golang.org/x/crypto/ripemd160"
)

func hashRipeMD160(data []byte) []byte {
	hasher := ripemd160.New()
	// hasher.Write(data)
	_, err := io.WriteString(hasher, string(data))
	if err != nil {
		panic(err)
	}
	return hasher.Sum(nil)
}

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

	// 从主私钥派生子私钥
	childPriKey1, err := rootPriKey.NewChildKey(0)
	if err != nil {
		panic(err)
	}
	fmt.Println(childPriKey1.B58Serialize())

	// // 从主公钥派生子公钥
	// childPubKey1, err := rootPubKey.NewChildKey(0)
	// if err != nil {
	// 	panic(err)
	// }
	// fmt.Println(childPubKey1.B58Serialize())
	// // 从子私钥派生子公钥
	// childPubKeyH1 := childPriKey1.PublicKey()
	// fmt.Println(childPubKeyH1.B58Serialize())

	myRootPriKey := BIP32NewRootPriKey(seed)
	a := myRootPriKey.ChildKey(0)
	fmt.Println(a)

	fmt.Println(hex.EncodeToString(hashRipeMD160([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06})))
	// fmt.Println(myRootPriKey.BIP32Base58())
	// myRootPubKey := myRootPriKey.BIP32PublicKey()
	// fmt.Println(myRootPubKey.BIP32Base58())
}
