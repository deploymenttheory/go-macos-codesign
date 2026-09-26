package codesign

import (
	"bytes"
	"crypto/sha1"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"text/scanner"
)

// Requirement grammar implemented here is deliberately bounded. Unimplemented
// predicates are rejected rather than being interpreted as true.
type requirementNode struct {
	op          uint32
	value       string
	slot        int32
	field       string
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
	case "anchor":
		if p.text != "apple" {
			return nil, unsupported("anchor predicate")
		}
		p.next()
		if p.text != "generic" {
			return nil, unsupported("only generic Apple anchors are implemented")
		}
		p.next()
		return &requirementNode{op: 15}, nil
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
		if op == 8 && p.token != scanner.String {
			return nil, malformed("quoted CDHash required")
		}
		value, err := p.stringValue()
		if err != nil {
			return nil, err
		}
		if op == 8 {
			b, err := hex.DecodeString(value)
			if err != nil || len(b) != 20 {
				return nil, fmt.Errorf("requirement: CDHash must contain 40 hexadecimal digits")
			}
			value = string(b)
		}
		return &requirementNode{op: op, value: value}, nil
	case "certificate":
		var slot int64
		switch p.text {
		case "leaf":
		case "root":
			slot = -1
		default:
			v, err := strconv.ParseInt(p.text, 10, 32)
			if err != nil || v < 0 || v > 31 {
				return nil, unsupported("certificate index")
			}
			slot = v
		}
		p.next()
		if p.text == "[" {
			return p.certificateField(int32(slot))
		}
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
		return &requirementNode{op: 4, slot: int32(slot), value: string(h)}, nil
	default:
		return nil, unsupported("requirement predicate " + strconv.Quote(s))
	}
}

func (p *requirementParser) certificateField(slot int32) (*requirementNode, error) {
	p.next()
	field := ""
	for p.text != "]" && p.token != scanner.EOF {
		field += p.text
		p.next()
	}
	if p.text != "]" {
		return nil, malformed("certificate field closing bracket")
	}
	p.next()
	n := &requirementNode{op: 11, slot: slot, field: field}
	if strings.HasPrefix(field, "field.") {
		var oid asn1.ObjectIdentifier
		for _, part := range strings.Split(strings.TrimPrefix(field, "field."), ".") {
			v, err := strconv.Atoi(part)
			if err != nil || v < 0 {
				return nil, malformed("certificate field OID")
			}
			oid = append(oid, v)
		}
		der, err := asn1.Marshal(oid)
		if err != nil {
			return nil, malformed("certificate field OID")
		}
		var raw asn1.RawValue
		_ = decodeDER(der, &raw)
		n.op, n.field = 14, string(raw.Bytes)
		// Apple's dumper emits an implicit matchExists with a comment.
		if p.text == "exists" {
			p.next()
		} else if p.token != scanner.EOF && p.text != "and" && p.text != "or" && p.text != ")" {
			return nil, unsupported("certificate extension match")
		}
		return n, nil
	}
	if field != "subject.CN" && field != "subject.OU" && field != "subject.O" {
		return nil, unsupported("certificate subject field")
	}
	if p.text != "=" {
		return nil, malformed("certificate subject equality")
	}
	p.next()
	value, err := p.stringValue()
	if err != nil {
		return nil, err
	}
	n.value = value
	return n, nil
}

func (p *requirementParser) stringValue() (string, error) {
	text := p.text
	var value string
	var err error
	switch {
	case p.token == scanner.String:
		value, err = strconv.Unquote(text)
	case p.token == scanner.Ident && simpleRequirementString(text):
		value = text
	case p.token == scanner.Int && strings.HasPrefix(text, "0x"):
		var data []byte
		data, err = hex.DecodeString(text[2:])
		value = string(data)
	default:
		return "", malformed("requirement string value")
	}
	p.next()
	return value, err
}
func parseRequirement(text string) (*requirementNode, error) {
	if len(text) > 1<<20 {
		return nil, malformed("requirement size limit")
	}
	p := &requirementParser{}
	p.scanner.Init(strings.NewReader(text))
	p.scanner.Mode = scanner.ScanIdents | scanner.ScanInts | scanner.ScanStrings | scanner.SkipComments | scanner.ScanComments
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
func appendRequirementData(dst []byte, s string) []byte {
	dst = append32(dst, uint32(len(s)))
	dst = append(dst, s...)
	for len(dst)%4 != 0 {
		dst = append(dst, 0)
	}
	return dst
}
func (n *requirementNode) encode(dst []byte) []byte {
	dst = append32(dst, n.op)
	switch n.op {
	case 11, 14:
		dst = append32(dst, uint32(n.slot))
		dst = appendRequirementData(dst, n.field)
		if n.op == 14 {
			dst = append32(dst, 0)
		} else {
			dst = append32(dst, 1)
			dst = appendRequirementData(dst, n.value)
		}
	case 2, 4, 8:
		if n.op == 4 {
			dst = append32(dst, uint32(n.slot))
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
	case 15:
		return appleAnchor(d.chain)
	case 11, 14:
		slot := int(n.slot)
		if slot < 0 {
			slot += len(d.chain)
		}
		if slot < 0 || slot >= len(d.chain) {
			return false
		}
		c := d.chain[slot]
		if n.op == 14 {
			var oid asn1.ObjectIdentifier
			if decodeDER(derWrap(6, []byte(n.field)), &oid) != nil {
				return false
			}
			return extension(c, oid.String()) != nil
		}
		oid := map[string]string{"subject.CN": "2.5.4.3", "subject.O": "2.5.4.10", "subject.OU": "2.5.4.11"}[n.field]
		v, err := subjectAttribute(c, oid)
		return err == nil && v != "" && v == n.value
	case 1:
		return true
	case 2:
		return d.Identifier == n.value
	case 8:
		return d.CDHash == hex.EncodeToString([]byte(n.value))
	case 4:
		cert := d.certificate
		if len(d.chain) > 0 {
			slot := int(n.slot)
			if slot < 0 {
				slot = len(d.chain) + slot
			}
			if slot < 0 || slot >= len(d.chain) {
				return false
			}
			cert = d.chain[slot].raw
		} else if n.slot != 0 {
			return false
		}
		if len(cert) == 0 {
			return false
		}
		h := sha1.Sum(cert)
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
	type span struct{ start, end uint64 }
	spans := make([]span, 0, count)
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
		spans = append(spans, span{off, off + n})
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	for i, span := range spans {
		if i > 0 && span.start < spans[i-1].end {
			return malformed("overlapping requirements")
		}
		_, err := decodeRequirement(data[span.start:span.end])
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
	readWord := func() (uint32, error) {
		if pos+4 > len(data) {
			return 0, malformed("requirement operand")
		}
		v := be.Uint32(data[pos:])
		pos += 4
		return v, nil
	}
	readString := func() (string, error) {
		n, err := readWord()
		if err != nil {
			return "", err
		}
		padded := (uint64(n) + 3) &^ uint64(3)
		if !rangeOK(uint64(pos), padded, uint64(len(data))) {
			return "", malformed("requirement field")
		}
		s := string(data[pos : uint64(pos)+uint64(n)])
		pos += int(padded)
		return s, nil
	}
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
		case 0, 1, 15:
		case 11, 14:
			slot, err := readWord()
			if err != nil {
				return nil, err
			}
			n.slot = int32(slot)
			if n.slot < -1 || n.slot > 31 {
				return nil, unsupported("certificate index")
			}
			n.field, err = readString()
			if err != nil {
				return nil, err
			}
			match, err := readWord()
			if err != nil {
				return nil, err
			}
			if n.op == 14 {
				var oid asn1.ObjectIdentifier
				if err := decodeDER(derWrap(6, []byte(n.field)), &oid); err != nil {
					return nil, err
				}
				if match != 0 {
					return nil, unsupported("certificate extension match")
				}
			} else {
				if match != 1 || n.field != "subject.CN" && n.field != "subject.OU" && n.field != "subject.O" {
					return nil, unsupported("certificate field match")
				}
				n.value, err = readString()
				if err != nil {
					return nil, err
				}
			}
		case 2, 4, 8:
			if n.op == 4 {
				if pos+4 > len(data) {
					return nil, malformed("certificate requirement slot")
				}
				n.slot = int32(be.Uint32(data[pos:]))
				if n.slot < -1 || n.slot > 31 {
					return nil, unsupported("certificate requirement index")
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
