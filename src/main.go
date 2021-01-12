package main

import (
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcutil/base58"
	"github.com/tyler-smith/go-bip32"
)

func main() {
	bytes, err := hex.DecodeString("0c1e24e5917779d297e14d45f14e1a1a")
	if err != nil {
		panic(err)
	}
	bip39 := NewBIP39ByFile("bip39wordlist-en.txt")
	words := bip39.GenerateWords(bytes)
	fmt.Println(words)
	seed := BIP39GetSeed(words, "")
	fmt.Println(hex.EncodeToString(seed))

	computerVoiceMasterKey, _ := bip32.NewMasterKey(seed)
	brst, err := computerVoiceMasterKey.Serialize()
	if err != nil {
		panic(err)
	}
	fmt.Println(123, base58.Encode(brst))

	b32 := BIP32NewRootPriKey(seed)
	fmt.Println(b32.SerializeBase58())
}
