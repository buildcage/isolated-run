package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"math/rand/v2"
	"reflect"
	"testing"
	"time"
	"unicode/utf8"
)

// plain is record as encoding/json writes it.
type plain record

// rawName is a name written as encoding/json would, but for each byte that is
// not part of valid UTF-8, which becomes the lone surrogate U+DC00 plus the byte.
type rawName string

func (n rawName) MarshalJSON() ([]byte, error) {
	s := string(n)
	out := []byte{'"'}
	for len(s) > 0 {
		valid := 0
		for valid < len(s) {
			r, size := utf8.DecodeRuneInString(s[valid:])
			if r == utf8.RuneError && size == 1 {
				break
			}
			valid += size
		}
		if valid > 0 {
			q, err := json.Marshal(s[:valid])
			if err != nil {
				return nil, err
			}
			out = append(out, q[1:len(q)-1]...)
			s = s[valid:]
			continue
		}
		out = fmt.Appendf(out, `\udc%02x`, s[0])
		s = s[1:]
	}
	return append(out, '"'), nil
}

// legacy is how the tracer wrote a record before appendRecord: a value whose
// MarshalJSON json.Encoder calls.
type legacy struct {
	r record
	t string
}

func (l legacy) MarshalJSON() ([]byte, error) {
	r := l.r
	if utf8.ValidString(r.Comm) && utf8.ValidString(r.Path) && utf8.ValidString(r.Name) &&
		utf8.ValidString(r.To) && utf8.ValidString(r.ToName) {
		return json.Marshal(struct {
			Time string `json:"t"`
			plain
		}{l.t, plain(r)})
	}
	return json.Marshal(struct {
		Time     string  `json:"t"`
		Kind     string  `json:"kind"`
		PID      uint32  `json:"pid"`
		PPID     uint32  `json:"ppid"`
		Comm     rawName `json:"comm"`
		Path     rawName `json:"path,omitempty"`
		Name     rawName `json:"name,omitempty"`
		To       rawName `json:"to,omitempty"`
		ToName   rawName `json:"to_name,omitempty"`
		Access   string  `json:"access,omitempty"`
		Flags    uint32  `json:"flags,omitempty"`
		Mode     string  `json:"mode,omitempty"`
		Owner    string  `json:"owner,omitempty"`
		Err      int32   `json:"err,omitempty"`
		Failed   bool    `json:"failed,omitempty"`
		Image    bool    `json:"image,omitempty"`
		Memfd    bool    `json:"memfd,omitempty"`
		Deleted  bool    `json:"deleted,omitempty"`
		Exchange bool    `json:"exchange,omitempty"`
		Syscall  string  `json:"syscall,omitempty"`
		Compat   bool    `json:"compat,omitempty"`
		Killed   bool    `json:"killed,omitempty"`
	}{l.t, r.Kind, r.PID, r.PPID, rawName(r.Comm), rawName(r.Path), rawName(r.Name),
		rawName(r.To), rawName(r.ToName), r.Access, r.Flags, r.Mode, r.Owner, r.Err,
		r.Failed, r.Image, r.Memfd, r.Deleted, r.Exchange, r.Syscall, r.Compat, r.Killed})
}

// reference is the line appendRecord must write, as legacy wrote it.
func reference(r record, ns int64) []byte {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(legacy{r, time.Unix(0, ns).UTC().Format(timeLayout)}); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// timeLayout is the "t" a line must carry.
const timeLayout = "2006-01-02T15:04:05.000Z07:00"

var testTime = time.Date(2026, 10, 6, 0, 0, 1, 500_000_000, time.UTC).UnixNano()

// One timeText for every time, as the recorder keeps one for every line.
func TestTimeTextMatchesFormat(t *testing.T) {
	var times []int64
	for _, base := range []int64{testTime, 0, -1, -1e9, -1e9 - 1, math.MinInt64, math.MaxInt64} {
		for _, d := range []int64{0, 1, 999_999, 1e6, 999_999_999, 1e9, -1, -1e9, 86_400e9} {
			if (d > 0 && base > math.MaxInt64-d) || (d < 0 && base < math.MinInt64-d) {
				continue
			}
			times = append(times, base+d)
		}
	}
	rng := rand.New(rand.NewPCG(1, 2))
	for range 1000 {
		ns := rng.Int64N(math.MaxInt64 - 1e10)
		for range 20 {
			ns += rng.Int64N(3e8)
			times = append(times, ns)
		}
		times = append(times, rng.Int64())
	}
	var text timeText
	for _, ns := range times {
		got := string(text.append(nil, ns))
		if want := time.Unix(0, ns).UTC().Format(timeLayout); got != want {
			t.Fatalf("%d: got %s, want %s", ns, got, want)
		}
	}
}

func TestRecordJSONKeepsBytesThatAreNotUTF8(t *testing.T) {
	r := record{Kind: "open", Comm: "c\xff", Path: "/tmp/a\xfe\xc3\xa9<", To: "\xed\xb3\xbf"}
	want := `{"t":"2026-10-06T00:00:01.500Z","kind":"open","pid":0,"ppid":0,"comm":"c\udcff","path":"/tmp/a\udcfeé\u003c","to":"\udced\udcb3\udcbf"}` + "\n"
	if got := string(appendRecord(nil, &r, &timeText{}, testTime)); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

// Every field set, so a field appendRecord leaves out or misnames shows.
func TestAppendRecordWritesEveryField(t *testing.T) {
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
	for _, comm := range []string{"c", "c\xff"} {
		r.Comm = comm
		got, want := appendRecord(nil, &r, &timeText{}, testTime), reference(r, testTime)
		if string(got) != string(want) {
			t.Fatalf("got  %s\nwant %s", got, want)
		}
	}
}

func FuzzAppendRecord(f *testing.F) {
	f.Add("open", "sh", "/tmp/x", "", "", "", "w", "", "", "", uint32(1), uint32(2), uint32(0), int32(0), uint16(0), int64(0))
	f.Add("open", "c", "a\fb\nc\rd\te", "", "", "", "r", "", "", "", uint32(1), uint32(2), uint32(0), int32(0), uint16(0), int64(0))
	f.Add("exec", "c\xff<", "a\u2028\x7f\b", "\xed\xb3\xbf", "\"\\", "\x00\x1f", "r&", "0644", "-1:0", "x>\xe1", uint32(1<<31), uint32(0), uint32(7), int32(-13), uint16(0x1ff), int64(-1))
	f.Fuzz(func(t *testing.T, kind, comm, path, name, to, toName, access, mode, owner, syscall string,
		pid, ppid, flags uint32, errno int32, bits uint16, ns int64) {
		r := record{
			Kind: kind, PID: pid, PPID: ppid, Comm: comm, Path: path, Name: name, To: to, ToName: toName,
			Access: access, Flags: flags, Mode: mode, Owner: owner, Err: errno, Syscall: syscall,
			Failed: bits&1 != 0, Image: bits&2 != 0, Memfd: bits&4 != 0, Deleted: bits&8 != 0,
			Exchange: bits&16 != 0, Compat: bits&32 != 0, Killed: bits&64 != 0,
		}
		if got, want := appendRecord(nil, &r, &timeText{}, ns), reference(r, ns); string(got) != string(want) {
			t.Fatalf("got  %s\nwant %s", got, want)
		}
	})
}
