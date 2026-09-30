package factory

import "testing"

func TestProtocolSet(t *testing.T) {
	tests := []struct {
		in      string
		want    Protocol
		wantErr bool
	}{
		{in: "61", want: Proto61},
		{in: "50", want: Proto50},
		{in: "", wantErr: true},
		{in: "1", wantErr: true},
		{in: "0", wantErr: true},
		{in: "256", wantErr: true},
		{in: "legacy", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			var p Protocol
			err := p.Set(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Set(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if err == nil && p != tt.want {
				t.Fatalf("Set(%q) = %d, want %d", tt.in, p, tt.want)
			}
		})
	}
}

func TestNewDefaultsProtocol(t *testing.T) {
	f := New("u", "p", "127.0.0.1", 80, "", "", 0)
	if f.proto != Proto61 {
		t.Fatalf("proto = %d, want %d", f.proto, Proto61)
	}
}
