package factory

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Post-2024 SendInfo encoding, from the httpd do_check_client VM.
// Ported from:
//
//	https://github.com/thuandt/zte_modem_tools/blob/ca4d4b9815e9890ba7e8f1213585acd9358beaf2/pwn.py
//	https://github.com/thuandt/zte_modem_tools/blob/ca4d4b9815e9890ba7e8f1213585acd9358beaf2/rsspwn.py
//	https://gist.github.com/ovn-is/d0331f781f5468dfaf107765fe095d85
//
// Those scripts cite
// https://github.com/douniwan5788/zte_modem_tools/issues/20#issuecomment-2854063148
// and https://github.com/douniwan5788/zte_modem_tools/issues/20#issuecomment-2849666205.
//
// The first four words choose the exponent and modulus used on the rest:
//
//	exponent = (word0^0x1687 mod 0x7561)*idx + (word1^0x1687 mod 0x7561)
//	modulus  = (word2^0x1687 mod 0x7561)*idx + (word3^0x1687 mod 0x7561)
//
// word0 and word2 encode 0, so idx (g_iRsaIndex) is multiplied by zero and
// drops out. word1 encodes 1 and word3 encodes 0x1687, leaving exponent 1 and
// modulus 0x1687. Each later word then decodes to one MAC byte. The ONU MAC
// from SendSq is the first group; the client MAC is repeated in the two
// groups after it. Words are restricted to a URL-safe alphabet and written
// as 4 little-endian bytes.
const (
	v3HeaderExp = 0x1687
	v3HeaderMod = 0x7561
	v3MACExp    = 1
	v3MACMod    = 0x1687

	sendInfoAlphabet = "lmaoztebcdfghijknpqrsuvwxy"
)

var (
	v3WordZero uint32
	v3WordOne  uint32
	v3WordMod  uint32
	v3MACWord  [256]uint32
)

func init() {
	need := map[uint32]struct{}{0: {}, 1: {}, v3MACMod: {}}
	found := make(map[uint32]uint32, len(need))
	forAlphabetWords(func(v uint32) bool {
		r := uint32(powMod(uint64(v), v3HeaderExp, v3HeaderMod))
		if _, want := need[r]; !want {
			return false
		}
		if _, ok := found[r]; !ok {
			found[r] = v
		}
		return len(found) == len(need)
	})
	var ok bool
	if v3WordZero, ok = found[0]; !ok {
		panic("v3 header encoding has no preimage for 0")
	}
	if v3WordOne, ok = found[1]; !ok {
		panic("v3 header encoding has no preimage for 1")
	}
	if v3WordMod, ok = found[v3MACMod]; !ok {
		panic("v3 header encoding has no preimage for 0x1687")
	}

	var seen [256]bool
	n := 0
	forAlphabetWords(func(v uint32) bool {
		b := byte(powMod(uint64(v), v3MACExp, v3MACMod) & 0xFF)
		if seen[b] {
			return false
		}
		seen[b] = true
		v3MACWord[b] = v
		n++
		return n == 256
	})
	if n != 256 {
		panic(fmt.Sprintf("v3 mac encoding covers %d/256 byte values", n))
	}
}

// forAlphabetWords visits 4-byte little-endian words whose bytes are drawn
// from sendInfoAlphabet, in the same order as itertools.product.
func forAlphabetWords(stop func(uint32) bool) {
	alpha := []byte(sendInfoAlphabet)
	for _, c0 := range alpha {
		for _, c1 := range alpha {
			for _, c2 := range alpha {
				for _, c3 := range alpha {
					v := uint32(c0) | uint32(c1)<<8 | uint32(c2)<<16 | uint32(c3)<<24
					if stop(v) {
						return
					}
				}
			}
		}
	}
}

func powMod(base, exp, mod uint64) uint64 {
	if mod == 1 {
		return 0
	}
	result := uint64(1)
	base %= mod
	for exp > 0 {
		if exp&1 == 1 {
			result = (result * base) % mod
		}
		base = (base * base) % mod
		exp >>= 1
	}
	return result
}

func appendV3Word(dst []byte, w uint32) []byte {
	return append(dst, byte(w), byte(w>>8), byte(w>>16), byte(w>>24))
}

// newSendInfoPlain builds the SendInfo.gch command for --proto 50.
// onuMAC is the 6 bytes carried in the SendSq response. clientMAC is the
// MAC the device associates with this TCP client.
func newSendInfoPlain(onuMAC, clientMAC []byte) (string, error) {
	if len(onuMAC) != 6 || len(clientMAC) != 6 {
		return "", errors.New("SendInfo MAC must be 6 bytes")
	}
	raw := make([]byte, 0, 22*4)
	raw = appendV3Word(raw, v3WordZero)
	raw = appendV3Word(raw, v3WordOne)
	raw = appendV3Word(raw, v3WordZero)
	raw = appendV3Word(raw, v3WordMod)
	for _, mac := range [][]byte{onuMAC, clientMAC, clientMAC} {
		for _, b := range mac {
			raw = appendV3Word(raw, v3MACWord[b])
		}
	}
	words := len(raw) / 4
	return fmt.Sprintf("SendInfo.gch?info=%d|%s", words, raw), nil
}

// parseNewSendSq splits a post-2024 SendSq body:
// re_rand=<server rand>&<seed>&<6-byte ONU MAC>.
// The seed is checked but not used: the SendInfo header cancels g_iRsaIndex,
// which is the only value the seed feeds.
func parseNewSendSq(body []byte) (serverRand int, onuMAC [6]byte, err error) {
	const prefix = "re_rand="
	rest, cut := bytes.CutPrefix(body, []byte(prefix))
	if !cut {
		return 0, onuMAC, fmt.Errorf("new handshake: expected re_rand=<rand>&<seed>&<mac>, got %q", body)
	}
	randField, rest, cut := bytes.Cut(rest, []byte("&"))
	if !cut {
		return 0, onuMAC, fmt.Errorf("new handshake: missing seed field in %q", body)
	}
	seedField, mac, cut := bytes.Cut(rest, []byte("&"))
	if !cut || len(mac) != 6 {
		return 0, onuMAC, fmt.Errorf("new handshake: ONU MAC field must be 6 bytes, got %q", body)
	}
	serverRand, err = strconv.Atoi(string(randField))
	if err != nil {
		return 0, onuMAC, fmt.Errorf("new handshake: bad server rand %q", randField)
	}
	if _, err = strconv.Atoi(string(seedField)); err != nil {
		return 0, onuMAC, fmt.Errorf("new handshake: bad seed %q", seedField)
	}
	copy(onuMAC[:], mac)
	return serverRand, onuMAC, nil
}

// verifyNewSendInfo replicates do_check_client for a --proto 50 command.
// idx is accepted and then canceled by the header words.
func verifyNewSendInfo(plain string, onuMAC, clientMAC []byte, idx int) bool {
	if len(onuMAC) != 6 || len(clientMAC) != 6 || idx < 0 {
		return false
	}
	_, after, cut := strings.Cut(plain, "|")
	if !cut {
		return false
	}
	raw := []byte(after)
	if len(raw) < 10*4 || len(raw)%4 != 0 {
		return false
	}
	words := make([]uint32, len(raw)/4)
	for n := range words {
		b := raw[n*4:]
		words[n] = uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
	}
	powHeader := func(w uint32) uint64 {
		return powMod(uint64(w), v3HeaderExp, v3HeaderMod)
	}
	exp := powHeader(words[0])*uint64(idx) + powHeader(words[1])
	mod := powHeader(words[2])*uint64(idx) + powHeader(words[3])
	if mod == 0 {
		return false
	}
	data := words[4:]
	buf := make([]byte, len(data))
	for i, w := range data {
		buf[i] = byte(powMod(uint64(w), exp, mod) & 0xFF)
	}
	if !bytes.Equal(buf[:6], onuMAC) {
		return false
	}
	for i := 11; i < len(buf); i += 6 {
		if bytes.Equal(buf[i-5:i+1], clientMAC) {
			return true
		}
	}
	return false
}
