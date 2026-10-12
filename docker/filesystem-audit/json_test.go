package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestRecordJSONKeepsBytesThatAreNotUTF8(t *testing.T) {
	r := record{Kind: "open", Comm: "c\xff", Path: "/tmp/a\xfe\xc3\xa9<", To: "\xed\xb3\xbf"}
	got, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"t":"","kind":"open","pid":0,"ppid":0,"comm":"c\udcff","path":"/tmp/a\udcfeé\u003c","to":"\udced\udcb3\udcbf"}`
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

// A record with a name that is not UTF-8 is written field for field as
// encoding/json writes record, every field set, but for that name's byte.
func TestRecordJSONMatchesItsFields(t *testing.T) {
	type plain record
	var r record
	v := reflect.ValueOf(&r).Elem()
	for i := range v.NumField() {
		f := v.Field(i)
		if !f.CanSet() {
			continue
		}
		switch f.Kind() {
		case reflect.String:
			f.SetString(v.Type().Field(i).Name)
		case reflect.Uint32:
			f.SetUint(1)
		case reflect.Int32:
			f.SetInt(1)
		case reflect.Bool:
			f.SetBool(true)
		default:
			t.Fatalf("field %s: set it here", v.Type().Field(i).Name)
		}
	}
	r.Comm = "c\xff"
	got, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	want, err := json.Marshal(plain(r))
	if err != nil {
		t.Fatal(err)
	}
	if w := strings.Replace(string(want), "c"+string(utf8.RuneError), `c\udcff`, 1); string(got) != w {
		t.Fatalf("got  %s\nwant %s", got, w)
	}
}
