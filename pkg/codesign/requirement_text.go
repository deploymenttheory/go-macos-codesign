package codesign

import (
	"encoding/asn1"
	"encoding/hex"
	"strconv"
	"strings"
)

// Canonical formatting follows Apple's reqdumper.cpp for the implemented
// expression subset. Parentheses preserve precedence; exists is implicit.
const requirementKeywords = " guest host designated library plugin or and always true never false identifier cdhash platform notarized legacy anchor apple generic certificate cert trusted info entitlement exists absent leaf root timestamp "

func simpleRequirementString(s string) bool {
	if s == "" || s[0] >= '0' && s[0] <= '9' || strings.Contains(requirementKeywords, " "+s+" ") {
		return false
	}
	for _, c := range []byte(s) {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func requirementString(s string) string {
	if simpleRequirementString(s) {
		return s
	}
	for _, c := range []byte(s) {
		if c < 32 && c != '\t' && c != '\n' && c != '\r' && c != '\v' && c != '\f' || c > 126 {
			return "0x" + hex.EncodeToString([]byte(s))
		}
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

func (n *requirementNode) text(level int) string {
	cert := func() string {
		if n.slot == -1 {
			return "certificate root"
		}
		if n.slot == 0 {
			return "certificate leaf"
		}
		return "certificate " + strconv.FormatInt(int64(n.slot), 10)
	}
	switch n.op {
	case 0:
		return "never"
	case 1:
		return "always"
	case 2:
		return "identifier " + requirementString(n.value)
	case 4:
		return cert() + ` = H"` + hex.EncodeToString([]byte(n.value)) + `"`
	case 8:
		return `cdhash H"` + hex.EncodeToString([]byte(n.value)) + `"`
	case 9:
		return "! " + n.left.text(0)
	case 15:
		return "anchor apple generic"
	case 11:
		return cert() + "[" + n.field + "] = " + requirementString(n.value)
	case 14:
		var oid asn1.ObjectIdentifier
		_ = decodeDER(derWrap(6, []byte(n.field)), &oid) // validated by decodeRequirement
		return cert() + "[field." + oid.String() + "] /* exists */"
	default: // validated opAnd/opOr nodes
		prec, op := 1, " and "
		if n.op == 7 {
			prec, op = 2, " or "
		}
		v := n.left.text(prec) + op + n.right.text(prec)
		if level < prec {
			v = "(" + v + ")"
		}
		return v
	}
}

func designatedRequirement(sig *Signature) (*requirementNode, error) {
	data := sig.find(SlotRequirements)
	if len(data) == 0 {
		return nil, nil
	}
	if err := validateRequirements(data); err != nil {
		return nil, err
	}
	for i := uint32(0); i < be.Uint32(data[8:]); i++ {
		if be.Uint32(data[12+i*8:]) == 3 {
			off := be.Uint32(data[16+i*8:])
			length := be.Uint32(data[off+4:])
			return decodeRequirement(data[off : off+length])
		}
	}
	return nil, nil
}
