package codesign

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"text/scanner"
)

// Requirement grammar implemented here is deliberately bounded. Unimplemented
// predicates are rejected rather than being interpreted as true.
type requirementNode struct {
	op          uint32
	value       string
	left, right *requirementNode
}
type requirementParser struct {
	scanner scanner.Scanner
	token   rune
	text    string
	depth   int
	nodes   int
}

func (p *requirementParser) next() { p.token = p.scanner.Scan(); p.text = p.scanner.TokenText() }
func (p *requirementParser) expression() (*requirementNode, error) {
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > 128 {
		return nil, malformed("requirement nesting limit")
	}
	n, err := p.conjunction()
	if err != nil {
		return nil, err
	}
	for p.text == "or" {
		p.next()
		r, err := p.conjunction()
		if err != nil {
			return nil, err
		}
		n = &requirementNode{op: 7, left: n, right: r}
	}
	return n, nil
}
func (p *requirementParser) conjunction() (*requirementNode, error) {
	n, err := p.atom()
	if err != nil {
		return nil, err
	}
	for p.text == "and" {
		p.next()
		r, err := p.atom()
		if err != nil {
			return nil, err
		}
		n = &requirementNode{op: 6, left: n, right: r}
	}
	return n, nil
}
func (p *requirementParser) atom() (*requirementNode, error) {
	p.nodes++
	if p.nodes > 4096 {
		return nil, malformed("requirement expression limit")
	}
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > 128 {
		return nil, malformed("requirement nesting limit")
	}
	s := p.text
	p.next()
	switch s {
	case "always", "true":
		return &requirementNode{op: 1}, nil
	case "never", "false":
		return &requirementNode{op: 0}, nil
	case "!", "not":
		n, err := p.atom()
		return &requirementNode{op: 9, left: n}, err
	case "(":
		n, err := p.expression()
		if err != nil {
			return nil, err
		}
		if p.text != ")" {
			return nil, fmt.Errorf("requirement: expected closing parenthesis")
		}
		p.next()
		return n, nil
	case "identifier", "cdhash":
		op := uint32(2)
		if s == "cdhash" {
			op = 8
			if p.text != "H" {
				return nil, fmt.Errorf("requirement: expected H followed by a quoted hash")
			}
			p.next()
		}
		if p.token != scanner.String {
			return nil, fmt.Errorf("requirement: expected quoted string")
		}
		value, err := strconv.Unquote(p.text)
		if err != nil {
			return nil, err
		}
		p.next()
		if op == 8 {
			b, err := hex.DecodeString(value)
			if err != nil || len(b) != 20 {
				return nil, fmt.Errorf("requirement: CDHash must contain 40 hexadecimal digits")
			}
			value = string(b)
		}
		return &requirementNode{op: op, value: value}, nil
	case "certificate":
		if p.text != "leaf" && p.text != "0" {
			return nil, unsupported("only leaf certificate hashes are implemented")
		}
		p.next()
		if p.text != "=" {
			return nil, malformed("expected certificate equality")
		}
		p.next()
		if p.text != "H" {
			return nil, malformed("expected certificate hash")
		}
		p.next()
		if p.token != scanner.String {
			return nil, malformed("expected quoted certificate hash")
		}
		value, err := strconv.Unquote(p.text)
		if err != nil {
			return nil, err
		}
		h, err := hex.DecodeString(value)
		if err != nil || len(h) != 20 {
			return nil, malformed("certificate hash must contain 40 hexadecimal digits")
		}
		p.next()
		return &requirementNode{op: 4, value: string(h)}, nil
	default:
		return nil, unsupported("requirement predicate " + strconv.Quote(s))
	}
}
func parseRequirement(text string) (*requirementNode, error) {
	if len(text) > 1<<20 {
		return nil, malformed("requirement size limit")
	}
	p := &requirementParser{}
	p.scanner.Init(strings.NewReader(text))
	p.scanner.Mode = scanner.ScanIdents | scanner.ScanStrings | scanner.SkipComments | scanner.ScanComments
	var scanErr error
	p.scanner.Error = func(_ *scanner.Scanner, msg string) { scanErr = fmt.Errorf("requirement: %s", msg) }
	p.next()
	n, err := p.expression()
	if err != nil {
		return nil, err
	}
	if scanErr != nil {
		return nil, scanErr
	}
	if p.token != scanner.EOF {
		return nil, fmt.Errorf("requirement: unexpected %q", p.text)
	}
	return n, nil
}

func append32(dst []byte, v uint32) []byte { return be.AppendUint32(dst, v) }
func (n *requirementNode) encode(dst []byte) []byte {
	dst = append32(dst, n.op)
	switch n.op {
	case 2, 4, 8:
		if n.op == 4 {
			dst = append32(dst, 0)
		}
		dst = append32(dst, uint32(len(n.value)))
		dst = append(dst, n.value...)
		for len(dst)%4 != 0 {
			dst = append(dst, 0)
		}
	case 6, 7:
		dst = n.left.encode(dst)
		dst = n.right.encode(dst)
	case 9:
		dst = n.left.encode(dst)
	}
	return dst
}

// CompileRequirement compiles one expression into Apple's standalone requirement blob.
func CompileRequirement(text string) ([]byte, error) {
	n, err := parseRequirement(text)
	if err != nil {
		return nil, err
	}
	return blob(MagicRequirement, n.encode(append32(nil, 1))), nil
}

// CompileRequirements compiles a designated requirement into a requirements set.
func CompileRequirements(text string) ([]byte, error) {
	text = strings.TrimSpace(text)
	if strings.HasPrefix(text, "designated") {
		_, rest, ok := strings.Cut(text, "=>")
		if !ok {
			return nil, fmt.Errorf("expected designated => expression")
		}
		text = strings.TrimSpace(rest)
	}
	req, err := CompileRequirement(text)
	if err != nil {
		return nil, err
	}
	return superblob(MagicRequirements, []Blob{{Slot: 3, Data: req}}), nil
}

func (n *requirementNode) matches(d Directory) bool {
	switch n.op {
	case 1:
		return true
	case 2:
		return d.Identifier == n.value
	case 8:
		return d.CDHash == hex.EncodeToString([]byte(n.value))
	case 4:
		if len(d.certificate) == 0 {
			return false
		}
		h := sha1.Sum(d.certificate)
		return bytes.Equal(h[:], []byte(n.value))
	case 6:
		return n.left.matches(d) && n.right.matches(d)
	case 7:
		return n.left.matches(d) || n.right.matches(d)
	case 9:
		return !n.left.matches(d)
	default:
		return false
	}
}

func EvaluateRequirement(text string, d Directory) (bool, error) {
	n, err := parseRequirement(text)
	if err != nil {
		return false, err
	}
	return n.matches(d), nil
}

func validateRequirements(data []byte) error {
	if len(data) < 12 || be.Uint32(data) != MagicRequirements || uint64(be.Uint32(data[4:])) != uint64(len(data)) {
		return malformed("requirements set")
	}
	count := be.Uint32(data[8:])
	if uint64(count)*8+12 > uint64(len(data)) {
		return malformed("requirements index")
	}
	seen := map[uint32]bool{}
	for i := uint32(0); i < count; i++ {
		slot := be.Uint32(data[12+i*8:])
		off := uint64(be.Uint32(data[16+i*8:]))
		if seen[slot] || off < uint64(12+count*8) || !rangeOK(off, 12, uint64(len(data))) {
			return malformed("requirement offset")
		}
		seen[slot] = true
		n := uint64(be.Uint32(data[off+4:]))
		if n < 12 || !rangeOK(off, n, uint64(len(data))) || be.Uint32(data[off:]) != MagicRequirement || be.Uint32(data[off+8:]) != 1 {
			return malformed("requirement blob")
		}
		_, err := decodeRequirement(data[off : off+n])
		if err != nil {
			return err
		}
	}
	return nil
}

func decodeRequirement(data []byte) (*requirementNode, error) {
	if len(data) < 12 || be.Uint32(data) != MagicRequirement || uint64(be.Uint32(data[4:])) != uint64(len(data)) || be.Uint32(data[8:]) != 1 {
		return nil, malformed("standalone requirement")
	}
	pos, nodes := 12, 0
	var read func(int) (*requirementNode, error)
	read = func(depth int) (*requirementNode, error) {
		nodes++
		if depth > 128 || nodes > 4096 {
			return nil, malformed("requirement expression limit")
		}
		if pos+4 > len(data) {
			return nil, malformed("requirement opcode")
		}
		n := &requirementNode{op: be.Uint32(data[pos:])}
		pos += 4
		switch n.op {
		case 0, 1:
		case 2, 4, 8:
			if n.op == 4 {
				if pos+4 > len(data) {
					return nil, malformed("certificate requirement slot")
				}
				if be.Uint32(data[pos:]) != 0 {
					return nil, unsupported("non-leaf certificate requirement")
				}
				pos += 4
			}
			if pos+4 > len(data) {
				return nil, malformed("requirement operand")
			}
			length := uint64(be.Uint32(data[pos:]))
			pos += 4
			padded := (length + 3) &^ uint64(3)
			if !rangeOK(uint64(pos), padded, uint64(len(data))) {
				return nil, malformed("requirement string")
			}
			if (n.op == 8 || n.op == 4) && length != 20 {
				return nil, malformed("requirement CDHash")
			}
			n.value = string(data[pos : uint64(pos)+length])
			pos += int(padded)
		case 6, 7, 9:
			var err error
			n.left, err = read(depth + 1)
			if err != nil {
				return nil, err
			}
			if n.op != 9 {
				n.right, err = read(depth + 1)
				if err != nil {
					return nil, err
				}
			}
		default:
			return nil, unsupported(fmt.Sprintf("requirement opcode %d", n.op))
		}
		return n, nil
	}
	n, err := read(0)
	if err != nil {
		return nil, err
	}
	if pos != len(data) {
		return nil, malformed("trailing requirement bytes")
	}
	return n, nil
}

// EvaluateRequirementBytes evaluates a compiled standalone requirement.
func EvaluateRequirementBytes(data []byte, d Directory) (bool, error) {
	n, err := decodeRequirement(data)
	if err != nil {
		return false, err
	}
	return n.matches(d), nil
}

func checkDesignatedRequirement(set []byte, d Directory) error {
	if len(set) == 0 {
		return nil
	}
	if err := validateRequirements(set); err != nil {
		return err
	}
	for i := uint32(0); i < be.Uint32(set[8:]); i++ {
		if be.Uint32(set[12+i*8:]) != 3 {
			continue
		}
		off := be.Uint32(set[16+i*8:])
		length := be.Uint32(set[off+4:])
		ok, err := EvaluateRequirementBytes(set[off:off+length], d)
		if err != nil {
			return err
		}
		if !ok {
			return ErrDesignatedRequirement
		}
	}
	return nil
}

// RequirementsBytes accepts compiled sets or textual designated requirements.
func RequirementsBytes(data []byte) ([]byte, error) {
	if len(data) >= 4 && be.Uint32(data) == MagicRequirements {
		return bytes.Clone(data), validateRequirements(data)
	}
	return CompileRequirements(string(data))
}
