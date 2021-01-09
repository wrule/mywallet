package main

// BytesToBits s
func BytesToBits(bytes []byte) []int {
	rst := []int{}
	for _, item := range bytes {
		for i := 7; i >= 0; i-- {
			num := (item >> i) & 0x01
			rst = append(rst, int(num))
		}
	}
	return rst
}

// BitsToBytes s
func BitsToBytes(bits []int) []byte {
	rst := []byte{}
	segNum := len(bits) / 8
	modNum := len(bits) % 8
	if modNum != 0 {
		panic("位数不是8的倍数")
	}
	for i := 0; i < segNum; i++ {
		start := i * 8
		bitSeg := bits[start : start+8]
		num := 0
		num += bitSeg[0] * 128
		num += bitSeg[1] * 64
		num += bitSeg[2] * 32
		num += bitSeg[3] * 16
		num += bitSeg[4] * 8
		num += bitSeg[5] * 4
		num += bitSeg[6] * 2
		num += bitSeg[7] * 1
		rst = append(rst, byte(num))
	}
	return rst
}
