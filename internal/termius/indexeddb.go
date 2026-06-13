package termius

import (
	"bytes"
	"encoding/binary"
	"math"
	"unicode/utf16"
)

const (
	indexedDBObjectStoreMetadataType     = 50
	indexedDBObjectStoreMetadataNameType = 0
	indexedDBObjectStoreDataIndexID      = 1
)

type indexedDBKeyPrefix struct {
	DatabaseID    uint64
	ObjectStoreID uint64
	IndexID       uint64
	Length        int
}

type indexedDBStoreKey struct {
	DatabaseID    uint64
	ObjectStoreID uint64
}

func decodeIndexedDBKeyPrefix(key []byte) (indexedDBKeyPrefix, bool) {
	if len(key) == 0 {
		return indexedDBKeyPrefix{}, false
	}
	header := key[0]
	databaseIDLength := int((header>>5)&0x07) + 1
	objectStoreIDLength := int((header>>2)&0x07) + 1
	indexIDLength := int(header&0x03) + 1
	offset := 1
	databaseID, ok := readLittleEndianPrefixInt(key, &offset, databaseIDLength)
	if !ok {
		return indexedDBKeyPrefix{}, false
	}
	objectStoreID, ok := readLittleEndianPrefixInt(key, &offset, objectStoreIDLength)
	if !ok {
		return indexedDBKeyPrefix{}, false
	}
	indexID, ok := readLittleEndianPrefixInt(key, &offset, indexIDLength)
	if !ok {
		return indexedDBKeyPrefix{}, false
	}
	return indexedDBKeyPrefix{
		DatabaseID:    databaseID,
		ObjectStoreID: objectStoreID,
		IndexID:       indexID,
		Length:        offset,
	}, true
}

func readLittleEndianPrefixInt(raw []byte, offset *int, length int) (uint64, bool) {
	if length < 1 || length > 8 || *offset+length > len(raw) {
		return 0, false
	}
	var value uint64
	for i := 0; i < length; i++ {
		value |= uint64(raw[*offset+i]) << (8 * i)
	}
	*offset += length
	return value, true
}

func decodeIndexedDBObjectStoreMetadataName(key []byte, value []byte) (indexedDBStoreKey, string, bool) {
	prefix, ok := decodeIndexedDBKeyPrefix(key)
	if !ok || prefix.ObjectStoreID != 0 || prefix.IndexID != 0 || prefix.Length >= len(key) {
		return indexedDBStoreKey{}, "", false
	}
	offset := prefix.Length
	if key[offset] != indexedDBObjectStoreMetadataType {
		return indexedDBStoreKey{}, "", false
	}
	offset++
	objectStoreID, ok := readIndexedDBVarInt(key, &offset)
	if !ok || offset >= len(key) || key[offset] != indexedDBObjectStoreMetadataNameType {
		return indexedDBStoreKey{}, "", false
	}
	offset++
	if offset != len(key) {
		return indexedDBStoreKey{}, "", false
	}
	name, ok := decodeIndexedDBString(value)
	if !ok || name == "" {
		return indexedDBStoreKey{}, "", false
	}
	return indexedDBStoreKey{DatabaseID: prefix.DatabaseID, ObjectStoreID: objectStoreID}, name, true
}

func readIndexedDBVarInt(raw []byte, offset *int) (uint64, bool) {
	var value uint64
	for shift := 0; shift < 64; shift += 7 {
		if *offset >= len(raw) {
			return 0, false
		}
		b := raw[*offset]
		*offset = *offset + 1
		value |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return value, true
		}
	}
	return 0, false
}

func decodeIndexedDBString(raw []byte) (string, bool) {
	if len(raw)%2 != 0 {
		return "", false
	}
	words := make([]uint16, len(raw)/2)
	for i := range words {
		words[i] = binary.BigEndian.Uint16(raw[i*2 : i*2+2])
	}
	return string(utf16.Decode(words)), true
}

func compareIndexedDBKeys(left []byte, right []byte) int {
	leftPrefix, leftOK := decodeIndexedDBKeyPrefix(left)
	rightPrefix, rightOK := decodeIndexedDBKeyPrefix(right)
	if !leftOK || !rightOK {
		return bytes.Compare(left, right)
	}
	if cmp := compareUint64(leftPrefix.DatabaseID, rightPrefix.DatabaseID); cmp != 0 {
		return cmp
	}
	if cmp := compareUint64(leftPrefix.ObjectStoreID, rightPrefix.ObjectStoreID); cmp != 0 {
		return cmp
	}
	if cmp := compareUint64(leftPrefix.IndexID, rightPrefix.IndexID); cmp != 0 {
		return cmp
	}
	leftRest := left[leftPrefix.Length:]
	rightRest := right[rightPrefix.Length:]
	if leftPrefix.ObjectStoreID != 0 && leftPrefix.IndexID >= indexedDBObjectStoreDataIndexID && leftPrefix.IndexID <= 3 {
		if cmp, ok := compareIndexedDBIDBKeys(leftRest, rightRest); ok {
			return cmp
		}
	}
	return bytes.Compare(leftRest, rightRest)
}

func compareUint64(left uint64, right uint64) int {
	switch {
	case left < right:
		return -1
	case left > right:
		return 1
	default:
		return 0
	}
}

func compareIndexedDBIDBKeys(left []byte, right []byte) (int, bool) {
	leftKey, leftOK := decodeIndexedDBIDBKey(left)
	rightKey, rightOK := decodeIndexedDBIDBKey(right)
	if !leftOK || !rightOK {
		return 0, false
	}
	if cmp := compareUint64(uint64(leftKey.kind), uint64(rightKey.kind)); cmp != 0 {
		return cmp, true
	}
	switch leftKey.kind {
	case indexedDBIDBKeyNumber, indexedDBIDBKeyDate:
		switch {
		case leftKey.number < rightKey.number:
			return -1, true
		case leftKey.number > rightKey.number:
			return 1, true
		default:
			return 0, true
		}
	case indexedDBIDBKeyString:
		return stringsCompare(leftKey.text, rightKey.text), true
	default:
		return bytes.Compare(left, right), true
	}
}

const (
	indexedDBIDBKeyString = 1
	indexedDBIDBKeyDate   = 2
	indexedDBIDBKeyNumber = 3
)

type indexedDBIDBKey struct {
	kind   byte
	number float64
	text   string
}

func decodeIndexedDBIDBKey(raw []byte) (indexedDBIDBKey, bool) {
	if len(raw) == 0 {
		return indexedDBIDBKey{}, false
	}
	switch raw[0] {
	case indexedDBIDBKeyNumber, indexedDBIDBKeyDate:
		if len(raw) < 9 {
			return indexedDBIDBKey{}, false
		}
		bits := binary.LittleEndian.Uint64(raw[1:9])
		return indexedDBIDBKey{kind: raw[0], number: math.Float64frombits(bits)}, true
	case indexedDBIDBKeyString:
		offset := 1
		length, ok := readIndexedDBVarInt(raw, &offset)
		byteLength := int(length) * 2
		if !ok || byteLength < 0 || offset+byteLength > len(raw) {
			return indexedDBIDBKey{}, false
		}
		text, ok := decodeIndexedDBString(raw[offset : offset+byteLength])
		if !ok {
			return indexedDBIDBKey{}, false
		}
		return indexedDBIDBKey{kind: raw[0], text: text}, true
	default:
		return indexedDBIDBKey{}, false
	}
}

func stringsCompare(left string, right string) int {
	switch {
	case left < right:
		return -1
	case left > right:
		return 1
	default:
		return 0
	}
}
