package main

// FirstHardenedKeyIndex 第一个强化密钥索引号
const FirstHardenedKeyIndex uint32 = 0x80000000

// IsHardenedKeyIndex 判断一个索引是否是强化密钥索引
func IsHardenedKeyIndex(index uint32) bool {
	return index >= FirstHardenedKeyIndex
}
