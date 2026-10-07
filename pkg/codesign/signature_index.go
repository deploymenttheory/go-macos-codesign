package codesign

import (
	"context"
	"errors"
	"io"
	"math/bits"
)

// A Patricia index has at most 32 branches per lookup, independent of insertion
// order or attacker-chosen keys. Nodes occupy geometrically grown working
// sections; only this fixed extent directory stays in Go memory. Growth follows
// validated entries, never the untrusted SuperBlob count.
type signatureIndex struct {
	ctx         context.Context
	extents     [32]workingSection
	count, root uint32
}

type signatureIndexNode struct{ key, value, bit, left, right uint32 }

const signatureIndexNodeSize = 20
const signatureIndexFirstExtent = 128

func signatureIndexPosition(id uint32) (int, int64) {
	row := uint64(id) - 1
	extent := bits.Len64(row/signatureIndexFirstExtent+1) - 1
	base := uint64(signatureIndexFirstExtent) * (uint64(1)<<extent - 1)
	return extent, int64(row-base) * signatureIndexNodeSize
}
func (x *signatureIndex) get(id uint32) (signatureIndexNode, error) {
	if err := x.ctx.Err(); err != nil {
		return signatureIndexNode{}, err
	}
	extent, at := signatureIndexPosition(id)
	var b [signatureIndexNodeSize]byte
	n, err := x.extents[extent].ReadAt(b[:], at)
	if n != len(b) {
		return signatureIndexNode{}, errors.Join(io.ErrUnexpectedEOF, err, x.ctx.Err())
	}
	if err != nil && err != io.EOF { //nolint:errorlint // A joined EOF plus a storage fault must remain an error.
		return signatureIndexNode{}, err
	}
	return signatureIndexNode{be.Uint32(b[:]), be.Uint32(b[4:]), be.Uint32(b[8:]), be.Uint32(b[12:]), be.Uint32(b[16:])}, x.ctx.Err()
}
func (x *signatureIndex) put(id uint32, node signatureIndexNode) error {
	if err := x.ctx.Err(); err != nil {
		return err
	}
	extent, at := signatureIndexPosition(id)
	var b [signatureIndexNodeSize]byte
	for i, v := range [...]uint32{node.key, node.value, node.bit, node.left, node.right} {
		be.PutUint32(b[i*4:], v)
	}
	n, err := x.extents[extent].WriteAt(b[:], at)
	if n != len(b) {
		err = errors.Join(io.ErrShortWrite, err)
	}
	return errors.Join(err, x.ctx.Err())
}
func (x *signatureIndex) append(node signatureIndexNode) (uint32, error) {
	id := x.count + 1
	if id == 0 {
		return 0, malformed("signature index node overflow")
	}
	extent, _ := signatureIndexPosition(id)
	if x.extents[extent].size == 0 {
		s, err := newWorkingSection(x.ctx, (int64(signatureIndexFirstExtent)<<extent)*signatureIndexNodeSize)
		if err != nil {
			return 0, err
		}
		x.extents[extent] = s
	}
	if err := x.put(id, node); err != nil {
		return 0, err
	}
	x.count = id
	return id, nil
}
func signatureIndexRight(key, bit uint32) bool { return key&(uint32(1)<<(31-bit)) != 0 }
func (x *signatureIndex) leaf(key uint32) (signatureIndexNode, bool, error) {
	id := x.root
	for id != 0 {
		n, err := x.get(id)
		if err != nil {
			return n, false, err
		}
		if n.bit == 32 {
			return n, true, nil
		}
		id = n.left
		if signatureIndexRight(key, n.bit) {
			id = n.right
		}
	}
	return signatureIndexNode{}, false, x.ctx.Err()
}
func (x *signatureIndex) find(key uint32) (uint32, bool, error) {
	n, exists, err := x.leaf(key)
	return n.value, exists && n.key == key, err
}
func (x *signatureIndex) insert(key, value uint32) (bool, error) {
	leaf, exists, err := x.leaf(key)
	if err != nil {
		return false, err
	}
	if exists && leaf.key == key {
		return true, nil
	}
	newLeaf, err := x.append(signatureIndexNode{key: key, value: value, bit: 32})
	if err != nil {
		return false, err
	}
	if !exists {
		x.root = newLeaf
		return false, nil
	}
	differing := uint32(bits.LeadingZeros32(key ^ leaf.key))
	var parentID uint32
	var parent signatureIndexNode
	at := x.root
	for {
		n, err := x.get(at)
		if err != nil {
			return false, err
		}
		if n.bit >= differing {
			break
		}
		parentID, parent = at, n
		at = n.left
		if signatureIndexRight(key, n.bit) {
			at = n.right
		}
	}
	branch := signatureIndexNode{key: key, bit: differing, left: newLeaf, right: at}
	if signatureIndexRight(key, differing) {
		branch.left, branch.right = at, newLeaf
	}
	branchID, err := x.append(branch)
	if err != nil {
		return false, err
	}
	if parentID == 0 {
		x.root = branchID
		return false, nil
	}
	if signatureIndexRight(key, parent.bit) {
		parent.right = branchID
	} else {
		parent.left = branchID
	}
	return false, x.put(parentID, parent)
}
func (x *signatureIndex) extreme(id uint32, right bool) (signatureIndexNode, bool, error) {
	for id != 0 {
		n, err := x.get(id)
		if err != nil {
			return n, false, err
		}
		if n.bit == 32 {
			return n, true, nil
		}
		id = n.left
		if right {
			id = n.right
		}
	}
	return signatureIndexNode{}, false, x.ctx.Err()
}
func (x *signatureIndex) overlaps(start, end uint32) (bool, error) {
	at := x.root
	var lower, upper uint32
	for at != 0 {
		n, err := x.get(at)
		if err != nil {
			return false, err
		}
		if n.bit == 32 {
			if n.key == start {
				return true, nil
			}
			if n.key < start {
				lower = at
			} else {
				upper = at
			}
			break
		}
		mask := ^uint32(0) << (32 - n.bit)
		if start&mask < n.key&mask {
			upper = at
			break
		}
		if start&mask > n.key&mask {
			lower = at
			break
		}
		if signatureIndexRight(start, n.bit) {
			lower, at = n.left, n.right
		} else {
			upper, at = n.right, n.left
		}
	}
	before, exists, err := x.extreme(lower, true)
	if err != nil {
		return false, err
	}
	if exists && before.value > start {
		return true, nil
	}
	after, exists, err := x.extreme(upper, false)
	return exists && after.key < end, err
}
