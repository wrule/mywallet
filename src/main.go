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
	bip39 := NewBIP39ByFile("bip39wordlist-en.txt")
	words := bip39.GenerateWords(bytes)
	fmt.Println(words)
	seed := BIP39GetSeed(words, "")
	fmt.Println(hex.EncodeToString(seed))
	computerVoiceMasterKey, _ := bip32.NewMasterKey(seed)
	fmt.Println(computerVoiceMasterKey.B58Serialize())
}
