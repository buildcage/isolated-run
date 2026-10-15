// Command stress makes file accesses as fast as it can for a while, from
// several threads, and prints how many it made.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

func main() {
	mode := flag.String("mode", "open", "prep, open, fail or ops")
	workers := flag.Int("workers", 4, "threads")
	dur := flag.Duration("dur", 5*time.Second, "how long")
	dir := flag.String("dir", "", "directory of the files to open, and to work in")
	flag.Parse()

	files := make([]string, 1000)
	for i := range files {
		files[i] = filepath.Join(*dir, "files", fmt.Sprintf("f%04d", i))
	}
	if *mode == "prep" {
		if err := os.MkdirAll(filepath.Join(*dir, "files"), 0o755); err != nil {
			panic(err)
		}
		for _, f := range files {
			if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
				panic(err)
			}
		}
		return
	}
	// Absolute names that do not exist, as a loader's library search makes.
	missing := make([]string, 1000)
	for i := range missing {
		missing[i] = fmt.Sprintf("/usr/lib/x86_64-linux-gnu/tls/haswell/libmissing%04d.so", i)
	}

	var total atomic.Int64
	deadline := time.Now().Add(*dur)
	var wg sync.WaitGroup
	for w := 0; w < *workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			runtime.LockOSThread()
			wdir := filepath.Join(*dir, fmt.Sprintf("w%d", w))
			d, f, g := filepath.Join(wdir, "d"), filepath.Join(wdir, "d", "f"), filepath.Join(wdir, "d", "g")
			if *mode == "ops" {
				if err := os.MkdirAll(wdir, 0o755); err != nil {
					panic(err)
				}
			}
			n := int64(0)
			for time.Now().Before(deadline) {
				for i := 0; i < 100; i++ {
					switch *mode {
					case "open":
						if fd, err := unix.Open(files[(w*131+i)%len(files)], unix.O_RDONLY, 0); err == nil {
							unix.Close(fd)
						}
					case "fail":
						unix.Open(missing[(w*131+i)%len(missing)], unix.O_RDONLY, 0)
					case "ops":
						unix.Mkdir(d, 0o755)
						if fd, err := unix.Open(f, unix.O_CREAT|unix.O_WRONLY, 0o644); err == nil {
							unix.Close(fd)
						}
						unix.Rename(f, g)
						unix.Unlink(g)
						unix.Rmdir(d)
					}
					n++
				}
			}
			total.Add(n)
		}(w)
	}
	wg.Wait()
	fmt.Printf("stress: ops=%d rate=%.0f\n", total.Load(), float64(total.Load())/dur.Seconds())
}
