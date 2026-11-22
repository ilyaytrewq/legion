package portscan

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestStateString(t *testing.T) {
	tests := []struct {
		state State
		want  string
	}{
		{StateUnknown, "unknown"},
		{StateOpen, "open"},
		{StateClosed, "closed"},
		{StateTimeout, "timeout"},
		{StateUnreachable, "unreachable"},
		{StateCanceled, "canceled"},
		{StateUnresolved, "unresolved"},
		{StateError, "error"},
		{State(200), "State(200)"},
	}
	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("State(%d).String() = %q, want %q", uint8(tt.state), got, tt.want)
		}
	}
}

func TestStateZeroValueIsNotOpen(t *testing.T) {
	var s State
	if s == StateOpen {
		t.Fatal("zero value of State is StateOpen")
	}
	if s != StateUnknown {
		t.Fatalf("zero value of State = %v, want StateUnknown", s)
	}
	var r Result
	if r.State == StateOpen {
		t.Fatal("zero value of Result reports an open port")
	}
}

func TestStateTextRoundTrip(t *testing.T) {
	for state := StateUnknown; state <= StateError; state++ {
		text, err := state.MarshalText()
		if err != nil {
			t.Fatalf("%v.MarshalText: %v", state, err)
		}
		if string(text) != state.String() {
			t.Errorf("MarshalText = %q, String = %q: must agree", text, state.String())
		}
		var got State
		if err := got.UnmarshalText(text); err != nil {
			t.Fatalf("UnmarshalText(%q): %v", text, err)
		}
		if got != state {
			t.Errorf("round-trip of %v gave %v", state, got)
		}
	}
}

func TestStateTextInvalid(t *testing.T) {
	if _, err := State(200).MarshalText(); !errors.Is(err, errInvalidState) {
		t.Errorf("State(200).MarshalText() error = %v, want %v", err, errInvalidState)
	}
	for _, text := range []string{"", "OPEN", "opened", "State(1)", "1"} {
		var s State
		if err := s.UnmarshalText([]byte(text)); !errors.Is(err, errInvalidState) {
			t.Errorf("UnmarshalText(%q) error = %v, want %v", text, err, errInvalidState)
		}
	}
}

func TestStateJSON(t *testing.T) {
	type doc struct {
		State State `json:"state"`
	}
	data, err := json.Marshal(doc{State: StateClosed})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if want := `{"state":"closed"}`; string(data) != want {
		t.Errorf("Marshal = %s, want %s", data, want)
	}
	var back doc
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if back.State != StateClosed {
		t.Errorf("Unmarshal gave %v, want %v", back.State, StateClosed)
	}
	if err := json.Unmarshal([]byte(`{"state":"nonsense"}`), &back); err == nil {
		t.Error("Unmarshal of an unknown state name succeeded, want error")
	}
}
