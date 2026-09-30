package factory

import (
	"cmp"
	"fmt"
	"strconv"
	"time"

	"github.com/go-resty/resty/v2"
)

// Protocol is the numeric suffix of the CheckLoginAuth versionXX field.
type Protocol uint8

const (
	// Proto61 is the original webFac handshake. CheckLoginAuth sends version61.
	// SendSq is either an empty body or newrand=<int>.
	Proto61 Protocol = 61
	// Proto50 is the three-field handshake. SendSq answers
	// re_rand=<server rand>&<seed>&<6-byte ONU MAC>, SendInfo carries both
	// MACs, and CheckLoginAuth sends version50.
	Proto50 Protocol = 50
)

// String returns the decimal version suffix.
func (p Protocol) String() string {
	return strconv.FormatUint(uint64(p), 10)
}

// Set parses a decimal version suffix. Only 61 and 50 are accepted.
func (p *Protocol) Set(s string) error {
	value, err := strconv.ParseUint(s, 10, 8)
	if err != nil || (Protocol(value) != Proto61 && Protocol(value) != Proto50) {
		return fmt.Errorf("must be %d or %d", Proto61, Proto50)
	}
	*p = Protocol(value)
	return nil
}

// Type is the kind shown for --proto in command-line help.
func (Protocol) Type() string { return "uint8" }

// Factory drives the reverse-engineered webFac HTTP flow of the ONU.
type Factory struct {
	user      string
	passwd    string
	ip        string
	port      int
	iface     string
	mac       string
	proto     Protocol
	cli       *resty.Client
	key       []byte
	onuMAC    [6]byte
	onuMACSet bool
}

// New builds a Factory for the given device and client settings. A non-empty
// mac is the only candidate used for the SendInfo payload (see ClientMAC).
// proto is Proto61 or Proto50. The zero value means Proto61.
func New(user string, passwd string, ip string, port int, iface string, mac string, proto Protocol) *Factory {
	proto = cmp.Or(proto, Proto61)
	return &Factory{
		user:   user,
		passwd: passwd,
		ip:     ip,
		port:   port,
		iface:  iface,
		mac:    mac,
		proto:  proto,
		cli: resty.New().SetHeader("User-Agent", "curl/8.8.0-DEV").
			SetTimeout(10 * time.Second).
			SetDebug(true).
			SetBaseURL(fmt.Sprintf("http://%s:%d", ip, port)),
	}
}
