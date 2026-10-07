package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestWriteIncomplete(t *testing.T) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	if err := writeIncomplete(enc, 0, 0); err != nil || buf.Len() != 0 {
		t.Fatalf("complete recording: err=%v wrote %q", err, buf.String())
	}
	if err := writeIncomplete(enc, 3, 0); err != nil {
		t.Fatal(err)
	}
	if got, want := buf.String(), `{"kind":"incomplete","dropped":3,"untracked":0}`+"\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
