package main

import (
	"encoding/hex"
	"fmt"

	"github.com/tyler-smith/go-bip32"
)

// Example address creation for a fictitious company ComputerVoice Inc. where
// each department has their own wallet to manage
func amain() {
	seed, err := hex.DecodeString("42762c87e931ba2f0638ea39d0683526b8c368112cd491e380a6a514c4eb4740a48bfffc36cbc836d358dae23444ea4881ac00622b5785097df32642cecf71c0b5df7f2719ebc5d0decb9f49a0b0fb1166a495f5b2ae3786146ed0c5a5f3bd535d141438cde203c3cf8524122ff7f122ab09aac04c95ad8b641d5a2c2725cc2930e9e19445d29e05f30efbf5d7470e5e43da32a5b9730cf8dc76b98e9b3a64b88849e7287a52e59c8979596ba3567d52db0e9f50af9598a345ea2168b99b8ff1622714d63ab17b24f401d8ff21156778a2118911768ba2b1ffc3aca1858561ae69427812477e9aa9271dd82a890dfc16ceedbcae738e34786ba108ee87fc2cc8")
	if err != nil {
		panic(err)
	}
	fmt.Printf("根种子(%d): %s\n", len(seed), hex.EncodeToString(seed))

	// Create master private key from seed
	computerVoiceMasterKey, _ := bip32.NewMasterKey(seed)
	fmt.Println("根私钥: ", computerVoiceMasterKey.B58Serialize())

	// Map departments to keys
	// There is a very small chance a given child index is invalid
	// If so your real program should handle this by skipping the index
	departmentKeys := map[string]*bip32.Key{}
	departmentKeys["Sales"], _ = computerVoiceMasterKey.NewChildKey(0)
	departmentKeys["Marketing"], _ = computerVoiceMasterKey.NewChildKey(1)
	departmentKeys["Engineering"], _ = computerVoiceMasterKey.NewChildKey(2)
	departmentKeys["Customer Support"], _ = computerVoiceMasterKey.NewChildKey(3)

	// Create public keys for record keeping, auditors, payroll, etc
	departmentAuditKeys := map[string]*bip32.Key{}
	departmentAuditKeys["Sales"] = departmentKeys["Sales"].PublicKey()
	departmentAuditKeys["Marketing"] = departmentKeys["Marketing"].PublicKey()
	departmentAuditKeys["Engineering"] = departmentKeys["Engineering"].PublicKey()
	departmentAuditKeys["Customer Support"] = departmentKeys["Customer Support"].PublicKey()

	// Print public keys
	for department, pubKey := range departmentAuditKeys {
		fmt.Println(department, pubKey)
	}
}
