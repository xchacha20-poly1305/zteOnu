package factory

import (
	"bytes"
	"testing"
)

// Published sample from the post-2024 do_check_client encoder:
// local/ONU group 11:22:33:44:55:66, client group 54:32:21:12:34:45.
const v3SamplePlain = "SendInfo.gch?info=22|apjdapalapjdafpemlbolledllsfmlelllfdllzsllqfmlbllltvllqallltllzkllqfmlbllltvllqallltllzk"

func TestNewSendInfoPlainSample(t *testing.T) {
	onu := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	client := []byte{0x54, 0x32, 0x21, 0x12, 0x34, 0x45}
	got, err := newSendInfoPlain(onu, client)
	if err != nil {
		t.Fatal(err)
	}
	if got != v3SamplePlain {
		t.Fatalf("plain mismatch:\n got %s\nwant %s", got, v3SamplePlain)
	}
	for _, index := range []int{0, 16, 59, 1234} {
		if !verifyNewSendInfo(got, onu, client, index) {
			t.Fatalf("sample fails do_check_client at idx %d", index)
		}
	}
	other := []byte{0x54, 0x32, 0x21, 0x12, 0x34, 0x46}
	if verifyNewSendInfo(got, onu, other, 1234) {
		t.Fatal("changed client MAC still verified")
	}
}

func TestParseNewSendSq(t *testing.T) {
	mac := []byte{0xd4, 0xab, 0x61, 0x7e, 0xf1, 0x62}
	body := append([]byte("re_rand=16&5681223&"), mac...)
	rand, got, err := parseNewSendSq(body)
	if err != nil {
		t.Fatal(err)
	}
	if rand != 16 {
		t.Fatalf("server rand %d, want 16", rand)
	}
	if !bytes.Equal(got[:], mac) {
		t.Fatalf("mac %x, want %x", got, mac)
	}
	if _, _, err := parseNewSendSq([]byte("re_rand=16")); err == nil {
		t.Fatal("expected error for a short re_rand body")
	}
}

func TestV3KeyIndex(t *testing.T) {
	// client rand 0 masks to 0, so the index is the server rand mod 60.
	key := getKeyPoolV3(0, 16)
	if len(key) != 24 {
		t.Fatalf("key length %d, want 24", len(key))
	}
	want := xorKeyPool(AesKeyPoolV3[16 : 16+24])
	if !bytes.Equal(key, want) {
		t.Fatalf("key %x, want pool[16:40] xor 0xA5 %x", key, want)
	}
	// rand 12, server 16: same mix the legacy v2 formula uses, different pool.
	masked := (0x1000193 * 12) & 0x3F
	idx := (masked ^ 16) % 60
	if got := getKeyPoolV3(12, 16); !bytes.Equal(got, xorKeyPool(AesKeyPoolV3[idx:idx+24])) {
		t.Fatalf("index %d key mismatch", idx)
	}
}
