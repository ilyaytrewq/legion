package portscan

import (
	"errors"
	"slices"
	"testing"
)

func collect(p PortSet) []uint16 {
	return slices.Collect(p.all())
}

func TestRange(t *testing.T) {
	tests := []struct {
		name      string
		from, to  int
		want      []uint16
		wantErrIs error
	}{
		{name: "single port", from: 80, to: 80, want: []uint16{80}},
		{name: "small range", from: 79, to: 82, want: []uint16{79, 80, 81, 82}},
		{name: "full range length", from: minPort, to: maxPort},
		{name: "port zero as start", from: 0, to: 10, wantErrIs: ErrInvalidPort},
		{name: "port zero as end", from: 0, to: 0, wantErrIs: ErrInvalidPort},
		{name: "above 65535", from: 1, to: 65536, wantErrIs: ErrInvalidPort},
		{name: "negative", from: -1, to: 10, wantErrIs: ErrInvalidPort},
		{name: "reversed range", from: 1000, to: 1, wantErrIs: ErrInvalidPortRange},
		{name: "reversed and invalid", from: 70000, to: 1, wantErrIs: ErrInvalidPort},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Range(tt.from, tt.to)
			if tt.wantErrIs != nil {
				if !errors.Is(err, tt.wantErrIs) {
					t.Fatalf("Range(%d, %d) error = %v, want error matching %v", tt.from, tt.to, err, tt.wantErrIs)
				}
				if got.Len() != 0 {
					t.Errorf("Range(%d, %d) returned a non-empty set together with an error", tt.from, tt.to)
				}
				return
			}
			if err != nil {
				t.Fatalf("Range(%d, %d) unexpected error: %v", tt.from, tt.to, err)
			}
			if want := tt.to - tt.from + 1; got.Len() != want {
				t.Errorf("Len() = %d, want %d", got.Len(), want)
			}
			if tt.want != nil {
				if ports := collect(got); !slices.Equal(ports, tt.want) {
					t.Errorf("ports = %v, want %v", ports, tt.want)
				}
			}
		})
	}
}

func TestList(t *testing.T) {
	t.Run("deduplicates silently", func(t *testing.T) {
		got, err := List(80, 443, 80, 22, 443, 80)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if want := []uint16{22, 80, 443}; !slices.Equal(collect(got), want) {
			t.Errorf("ports = %v, want %v", collect(got), want)
		}
		if got.Len() != 3 {
			t.Errorf("Len() = %d, want 3", got.Len())
		}
	})

	t.Run("empty list", func(t *testing.T) {
		if _, err := List(); !errors.Is(err, ErrNoPorts) {
			t.Errorf("List() error = %v, want %v", err, ErrNoPorts)
		}
	})

	for _, port := range []int{0, -1, 65536, 1 << 20} {
		if _, err := List(80, port); !errors.Is(err, ErrInvalidPort) {
			t.Errorf("List(80, %d) error = %v, want %v", port, err, ErrInvalidPort)
		}
	}
}

func TestUnion(t *testing.T) {
	a, err := Range(80, 82)
	if err != nil {
		t.Fatal(err)
	}
	b, err := List(81, 443)
	if err != nil {
		t.Fatal(err)
	}

	got := Union(a, b, PortSet{})
	if want := []uint16{80, 81, 82, 443}; !slices.Equal(collect(got), want) {
		t.Errorf("Union ports = %v, want %v", collect(got), want)
	}
	if got.Len() != 4 {
		t.Errorf("Union Len() = %d, want 4", got.Len())
	}

	if n := Union().Len(); n != 0 {
		t.Errorf("Union() Len() = %d, want 0", n)
	}
	if n := Union(PortSet{}, PortSet{}).Len(); n != 0 {
		t.Errorf("Union of empty sets Len() = %d, want 0", n)
	}

	if a.Len() != 3 || b.Len() != 2 {
		t.Errorf("Union mutated its operands: a.Len() = %d, b.Len() = %d", a.Len(), b.Len())
	}
}

func TestZeroValuePortSet(t *testing.T) {
	var p PortSet
	if p.Len() != 0 {
		t.Errorf("Len() = %d, want 0", p.Len())
	}
	if p.String() != "" {
		t.Errorf("String() = %q, want empty", p.String())
	}
	if ports := collect(p); len(ports) != 0 {
		t.Errorf("ports = %v, want none", ports)
	}
}

func TestParsePorts(t *testing.T) {
	tests := []struct {
		name      string
		spec      string
		want      []uint16
		wantErrIs error
	}{
		{name: "single", spec: "80", want: []uint16{80}},
		{name: "list", spec: "22,80,443", want: []uint16{22, 80, 443}},
		{name: "range", spec: "80-83", want: []uint16{80, 81, 82, 83}},
		{name: "mixed", spec: "443,80-82", want: []uint16{80, 81, 82, 443}},
		{name: "unsorted input is sorted", spec: "443,22,80", want: []uint16{22, 80, 443}},
		{name: "overlapping ranges collapse", spec: "80-84,82-86", want: []uint16{80, 81, 82, 83, 84, 85, 86}},
		{name: "duplicates collapse", spec: "80,80,80", want: []uint16{80}},
		{name: "whitespace is ignored", spec: " 22 , 80 - 82 ", want: []uint16{22, 80, 81, 82}},
		{name: "single-port range", spec: "80-80", want: []uint16{80}},
		{name: "boundaries", spec: "1,65535", want: []uint16{1, 65535}},
		{name: "leading zeros", spec: "080", want: []uint16{80}},

		{name: "empty", spec: "", wantErrIs: ErrNoPorts},
		{name: "whitespace only", spec: "   ", wantErrIs: ErrNoPorts},
		{name: "port zero", spec: "0", wantErrIs: ErrInvalidPort},
		{name: "port zero in range", spec: "0-10", wantErrIs: ErrInvalidPort},
		{name: "above 65535", spec: "65536", wantErrIs: ErrInvalidPort},
		{name: "far above 65535", spec: "4294967296", wantErrIs: ErrInvalidPort},
		{name: "32-bit wrapping value", spec: "4294967376", wantErrIs: ErrInvalidPort},
		{name: "reversed range", spec: "1000-1", wantErrIs: ErrInvalidPortRange},
		{name: "trailing comma", spec: "80,", wantErrIs: ErrInvalidPort},
		{name: "empty item", spec: "80,,443", wantErrIs: ErrInvalidPort},
		{name: "not a number", spec: "http", wantErrIs: ErrInvalidPort},
		{name: "negative", spec: "-80", wantErrIs: ErrInvalidPort},
		{name: "signed", spec: "+80", wantErrIs: ErrInvalidPort},
		{name: "hex", spec: "0x50", wantErrIs: ErrInvalidPort},
		{name: "float", spec: "80.5", wantErrIs: ErrInvalidPort},
		{name: "triple range", spec: "80-90-100", wantErrIs: ErrInvalidPort},
		{name: "open-ended range", spec: "80-", wantErrIs: ErrInvalidPort},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePorts(tt.spec)
			switch {
			case tt.wantErrIs != nil:
				if !errors.Is(err, tt.wantErrIs) {
					t.Fatalf("ParsePorts(%q) error = %v, want error matching %v", tt.spec, err, tt.wantErrIs)
				}
			default:
				if err != nil {
					t.Fatalf("ParsePorts(%q) unexpected error: %v", tt.spec, err)
				}
				if ports := collect(got); !slices.Equal(ports, tt.want) {
					t.Fatalf("ParsePorts(%q) = %v, want %v", tt.spec, ports, tt.want)
				}
				if got.Len() != len(tt.want) {
					t.Errorf("Len() = %d, want %d", got.Len(), len(tt.want))
				}
			}
			if err != nil && got.Len() != 0 {
				t.Errorf("ParsePorts(%q) returned a non-empty set together with an error", tt.spec)
			}
		})
	}
}

func TestPortSetString(t *testing.T) {
	tests := []struct {
		spec string
		want string
	}{
		{spec: "80", want: "80"},
		{spec: "443,22,80", want: "22,80,443"},
		{spec: "80-82", want: "80-82"},
		{spec: "80,81", want: "80-81"},
		{spec: "80,82", want: "80,82"},
		{spec: "1-3,7,9-10", want: "1-3,7,9-10"},
		{spec: " 22 , 80 - 82 , 81 ", want: "22,80-82"},
		{spec: "1-65535", want: "1-65535"},
	}
	for _, tt := range tests {
		t.Run(tt.spec, func(t *testing.T) {
			p, err := ParsePorts(tt.spec)
			if err != nil {
				t.Fatalf("ParsePorts(%q): %v", tt.spec, err)
			}
			if got := p.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
			again, err := ParsePorts(p.String())
			if err != nil {
				t.Fatalf("ParsePorts(%q): %v", p.String(), err)
			}
			if again.String() != p.String() {
				t.Errorf("round-trip = %q, want %q", again.String(), p.String())
			}
		})
	}
}

func FuzzParsePorts(f *testing.F) {
	for _, seed := range []string{
		"", "0", "1", "80", "22,80,443", "80-90", "1000-1", "65535", "65536",
		" 1 - 3 ", "-", ",", "80,,90", "1-65535", "0x10", "+1", "1-2-3",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, spec string) {
		p, err := ParsePorts(spec)
		if err != nil {
			if p.Len() != 0 {
				t.Fatalf("ParsePorts(%q) returned %d ports together with error %v", spec, p.Len(), err)
			}
			return
		}
		if p.Len() == 0 {
			t.Fatalf("ParsePorts(%q) succeeded with an empty set", spec)
		}

		n := 0
		prev := -1
		for port := range p.all() {
			if port < minPort || port > maxPort {
				t.Fatalf("ParsePorts(%q) yielded out-of-range port %d", spec, port)
			}
			if int(port) <= prev {
				t.Fatalf("ParsePorts(%q) yielded %d after %d: not ascending", spec, port, prev)
			}
			prev = int(port)
			n++
		}
		if n != p.Len() {
			t.Fatalf("ParsePorts(%q): Len() = %d but iteration yielded %d ports", spec, p.Len(), n)
		}

		again, err := ParsePorts(p.String())
		if err != nil {
			t.Fatalf("ParsePorts(%q) = %q, which failed to parse: %v", spec, p.String(), err)
		}
		if again.Len() != p.Len() || again.String() != p.String() {
			t.Fatalf("round-trip of %q: %q (%d ports) != %q (%d ports)",
				spec, again.String(), again.Len(), p.String(), p.Len())
		}
	})
}
