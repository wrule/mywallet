package main

import (
	"crypto/hmac"
	"crypto/sha512"
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

	h := hmac.New(sha512.New, []byte("Bitcoin seed"))
	h.Write(seed)
	rst := h.Sum(nil)
	fmt.Println(hex.EncodeToString(rst), len(rst))
	keyBytes := rst[:32]
	// codeBytes := rst[32:]

	fmt.Println(base58.Encode(keyBytes))

	computerVoiceMasterKey, _ := bip32.NewMasterKey(seed)
	brst, err := computerVoiceMasterKey.Serialize()
	if err != nil {
		panic(err)
	}
	fmt.Println(123, base58.Encode(brst))
}
