package part_test

import "hash/crc32"

func crc(b []byte) uint32 { return crc32.ChecksumIEEE(b) }
