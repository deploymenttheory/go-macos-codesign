package cli

import (
	"math"
	"strconv"
	"strings"
)

// The pinned CLI accepts name prefixes, but not the manual's comma lists.
// Its numeric form consumes a C base-0 prefix and truncates to a 32-bit mask.
// Unknown policy bits remain explicitly unsupported by parse, never forwarded.
func parseStrictSelector(text string) (mask uint32, disable bool, err error) {
	if text == "" {
		return 0x280, false, nil
	}
	if text[0] >= '0' && text[0] <= '9' {
		base, start := 10, 0
		if text[0] == '0' {
			base = 8
			if len(text) > 2 && (text[1] == 'x' || text[1] == 'X') && strings.ContainsRune("0123456789abcdefABCDEF", rune(text[2])) {
				base, start = 16, 2
			}
		}
		end := start
		for end < len(text) {
			digit := strings.IndexByte("0123456789abcdef", strings.ToLower(text[end : end+1])[0])
			if digit < 0 || digit >= base {
				break
			}
			end++
		}
		value, parseErr := strconv.ParseUint(text[start:end], base, 64)
		if parseErr != nil {
			value = math.MaxUint64
		}
		return uint32(value), false, nil
	}
	for _, item := range []struct {
		name string
		mask uint32
	}{{"symlinks", 0x80}, {"sideband", 0x200}, {"all", 0x280}, {"none", 0}} {
		if strings.HasPrefix(item.name, text) {
			return item.mask, item.name == "none", nil
		}
	}
	return 0, false, &nativeCLIError{"invalid strict option - " + text, 1}
}
