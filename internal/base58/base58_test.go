package base58

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// The expected strings were computed independently (with Python).
func TestEncodeDecode(t *testing.T) {
	tests := []struct {
		Hex      string
		Expected string
	}{
		{Hex: "", Expected: ""},
		{Hex: "48656c6c6f20576f726c6421", Expected: "2NEpo7TZRRrLZSi2U"},
		{Hex: "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e", Expected: "USm3fpXnKG5EUBx2ndxBDMPVciP5hGey2Jh4NDv6gmeo1LkMeiKrLJUUBk6Z"},
		{Hex: "0000287fb4cd", Expected: "11233QC4"},
		{Hex: "00", Expected: "1"},
	}

	for _, test := range tests {
		p, _ := hex.DecodeString(test.Hex)

		if actual := Encode(p); test.Expected != actual {
			t.Errorf("For %s, expected %q but actually got %q.", test.Hex, test.Expected, actual)
		}

		decoded, err := Decode(test.Expected)
		if nil != err {
			t.Errorf("For %q, did not expect an error but actually got one: %s", test.Expected, err)
			continue
		}
		if !bytes.Equal(p, decoded) {
			t.Errorf("For %q, expected %x but actually got %x.", test.Expected, p, decoded)
		}
	}

	for _, s := range []string{"0", "O", "I", "l", "+", "abc!"} {
		if _, err := Decode(s); ErrBadCharacter != err {
			t.Errorf("For %q, expected ErrBadCharacter but actually got: %v", s, err)
		}
	}
}
