package main

import (
	"crypto/sha256"
	"crypto/sha512"
	"io/ioutil"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// BIP39 bip39标准实例
type BIP39 struct {
	words []string
}

// GenerateWords 根据字节切片获取助记词切片
func (me *BIP39) GenerateWords(bytes []byte) string {
	bits := BIP39BytesAddCheckInfo(bytes)
	segNum := len(bits) / 11
	modNum := len(bits) % 11
	if modNum != 0 {
		panic("位数不是11的整数倍")
	}
	rst := []string{}
	for i := 0; i < segNum; i++ {
		start := i * 11
		bitSeg := bits[start : start+11]
		num := 0
		num += bitSeg[0] * 1024
		num += bitSeg[1] * 512
		num += bitSeg[2] * 256
		num += bitSeg[3] * 128
		num += bitSeg[4] * 64
		num += bitSeg[5] * 32
		num += bitSeg[6] * 16
		num += bitSeg[7] * 8
		num += bitSeg[8] * 4
		num += bitSeg[9] * 2
		num += bitSeg[10] * 1
		rst = append(rst, me.words[num])
	}
	return strings.Join(rst, " ")
}

// BIP39BytesAddCheckInfo 为字节切片添加校验尾部并且生成位切片
func BIP39BytesAddCheckInfo(bytes []byte) []int {
	bits := BytesToBits(bytes)
	checkLen := len(bits) / 32
	h := sha256.New()
	h.Write(bytes)
	hashBytes := h.Sum(nil)
	hashBits := BytesToBits(hashBytes)
	bits = append(bits, hashBits[:checkLen]...)
	return bits
}

// BIP39GetSeed 根据助记词文本和密码获取种子
func BIP39GetSeed(words string, pwd string) []byte {
	return pbkdf2.Key([]byte(words), []byte("mnemonic"+pwd), 2048, 64, sha512.New)
}

// NewBIP39ByWords 构造函数，从切片构造
func NewBIP39ByWords(words []string) *BIP39 {
	return &BIP39{
		words: words,
	}
}

// NewBIP39ByFile 构造函数，从文件构造
func NewBIP39ByFile(filePath string) *BIP39 {
	return NewBIP39ByWords(BIP39ReadWordList(filePath))
}

// BIP39ReadWordList 从文件中读取助记词词典列表
func BIP39ReadWordList(filePath string) []string {
	bytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		panic(err)
	}
	rst := []string{}
	for _, item := range strings.Split(string(bytes), "\n") {
		itemTrimed := strings.TrimSpace(item)
		if len(itemTrimed) > 0 {
			rst = append(rst, itemTrimed)
		}
	}
	if len(rst) != 2048 {
		panic("词典文件内单词数量不为2048")
	}
	return rst
}
