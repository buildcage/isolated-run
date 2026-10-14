
## Process Activity Report

### Executed Programs

| Path | Count |
| --- | ---: |
| `/usr/bin/cat` | 3 |
| `/usr/bin/mv` | 1 |
| `/usr/bin/rm` | 1 |
| `/usr/bin/touch` | 1 |
| `/usr/bin/mkdir` | 5 |
| `/usr/bin/python3.12` | 6 |
| `/usr/bin/chmod` | 2 |
| `/usr/bin/chown` | 1 |
| `./A/run.sh` | 1 |
| `/usr/bin/mkfifo` | 1 |
| `memfd:"probe-memfd"` | 1 |
| `./gone-bin` (deleted) | 1 |
| `/usr/bin/dash` | 1 |
| `/usr/bin/true` | 1 |
| `/usr/bin/uname` | 1 |
| `./int80` | 1 |

<details>
<summary>Accessed Paths (75)</summary>

<sub>R read · W write · X exec · M move · L link · D delete · A attr · lowercase = failed · ! = denied</sub>

| Program | Access | Path |
| --- | --- | --- |
| `bash` | W | `./A/run.sh` |
| `bash` | W | `./execd.txt` |
| `bash` | W | `./mapped.bin` |
| `bash` | W | `./mprotected-rwx.bin` |
| `bash` | W | `./mprotected.bin` |
| `bash` | W | `./probe.txt` |
| `bash` | W | `./ro-mapped.bin` |
| `bash` | W | `./shared.txt` |
| `bash` | W | `/dev/null` |
| `bash` | rw | `/dev/tty` |
| `bash` | R | `/etc/locale.alias` |
| `bash` | R | `/usr/lib/locale/**` |
| `bash` | R | `/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache` |
| `/usr/bin/cat` | W | `./execd.txt` |
| `/usr/bin/cat` | r | `./sub/missing.txt` |
| `/usr/bin/cat` | W | `/dev/null` |
| `/usr/bin/cat` | R | `/etc/hostname` |
| `/usr/bin/cat` | R | `/etc/locale.alias` |
| `/usr/bin/cat` | R | `/usr/lib/locale/**` |
| `/usr/bin/cat` | R | `/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache` |
| `/usr/bin/mv` | M | `./probe.txt` |
| `/usr/bin/mv` | R | `/etc/locale.alias` |
| `/usr/bin/mv` | R | `/proc/filesystems` |
| `/usr/bin/mv` | R | `/usr/lib/locale/**` |
| `/usr/bin/mv` | R | `/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache` |
| `/usr/bin/rm` | D | `./probe2.txt` |
| `/usr/bin/rm` | R | `/etc/locale.alias` |
| `/usr/bin/rm` | R | `/usr/lib/locale/**` |
| `/usr/bin/rm` | R | `/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache` |
| `/usr/bin/touch` | WA | `./subshell.txt` |
| `/usr/bin/touch` | R | `/etc/locale.alias` |
| `/usr/bin/touch` | R | `/usr/lib/locale/**` |
| `/usr/bin/touch` | R | `/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache` |
| `/usr/bin/mkdir` | W | `./A` |
| `/usr/bin/mkdir` | w! | `./root-owned/x` |
| `/usr/bin/mkdir` | W | `./sub` |
| `/usr/bin/mkdir` | W | `/dev/null` |
| `/usr/bin/mkdir` | R | `/etc/locale.alias` |
| `/usr/bin/mkdir` | R | `/proc/filesystems` |
| `/usr/bin/mkdir` | R | `/usr/lib/locale/**` |
| `/usr/bin/mkdir` | R | `/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache` |
| `/usr/bin/mkdir` | w! | `/usr/local/buildcage-ro-probe` |
| `/usr/bin/python3.12` | w | `./fifo` |
| `/usr/bin/python3.12` | WDA | `./gone-bin` |
| `/usr/bin/python3.12` | R | `./mapped.bin` |
| `/usr/bin/python3.12` | RW | `./mprotected-rwx.bin` |
| `/usr/bin/python3.12` | RW | `./mprotected.bin` |
| `/usr/bin/python3.12` | d | `./sub/gone` |
| `/usr/bin/python3.12` | R | `/etc/locale.alias` |
| `/usr/bin/python3.12` | R | `/proc/<pid>/stat` |
| `/usr/bin/python3.12` | R | `/usr/**` |
| `/usr/bin/python3.12` | W | `memfd:"probe-memfd"` |
| `/usr/bin/chmod` | A | `./A/run.sh` |
| `/usr/bin/chmod` | a! | `./root-owned.txt` |
| `/usr/bin/chmod` | W | `/dev/null` |
| `/usr/bin/chmod` | R | `/etc/locale.alias` |
| `/usr/bin/chmod` | R | `/usr/lib/locale/**` |
| `/usr/bin/chmod` | R | `/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache` |
| `/usr/bin/chown` | a! | `./root-owned.txt` |
| `/usr/bin/chown` | W | `/dev/null` |
| `/usr/bin/chown` | R | `/etc/**` |
| `/usr/bin/chown` | R | `/usr/lib/locale/**` |
| `/usr/bin/chown` | R | `/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache` |
| `/usr/bin/mkfifo` | W | `./fifo` |
| `/usr/bin/mkfifo` | R | `/etc/locale.alias` |
| `/usr/bin/mkfifo` | R | `/proc/filesystems` |
| `/usr/bin/mkfifo` | R | `/usr/lib/locale/**` |
| `/usr/bin/mkfifo` | R | `/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache` |
| `/usr/bin/dash` | W | `./shared.txt` |
| `/usr/bin/true` | R | `/etc/locale.alias` |
| `/usr/bin/true` | R | `/usr/lib/locale/**` |
| `/usr/bin/true` | R | `/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache` |
| `/usr/bin/uname` | R | `/etc/locale.alias` |
| `/usr/bin/uname` | R | `/usr/lib/locale/**` |
| `/usr/bin/uname` | R | `/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache` |

</details>

<details>
<summary>🔍 Process details</summary>

<sub>first-last access since the proxy started · flags · command · path</sub>

```
00:06.625:           rw  bash            /dev/tty
00:06.625:           R   bash            /usr/lib/locale/**
00:06.625:           R   bash            /etc/locale.alias
00:06.625:           R   bash            /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
00:06.626-00:06.659: W   bash            /dev/null
00:06.626-00:06.768: X   cat             /usr/bin/cat
00:06.626-00:06.769: R   cat             /usr/lib/locale/**
00:06.626-00:06.768: R   cat             /etc/locale.alias
00:06.626-00:06.768: R   cat             /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
00:06.627-00:06.769: R   cat             /etc/hostname
00:06.627-00:06.634: W   cat             /dev/null
00:06.627:           W   bash            ./probe.txt
00:06.627:           X   mv              /usr/bin/mv
00:06.628:           R   mv              /proc/filesystems
00:06.628:           R   mv              /usr/lib/locale/**
00:06.628:           R   mv              /etc/locale.alias
00:06.628:           R   mv              /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
00:06.628:           M   mv              ./probe.txt
00:06.629:           X   rm              /usr/bin/rm
00:06.629-00:06.630: R   rm              /usr/lib/locale/**
00:06.629:           R   rm              /etc/locale.alias
00:06.629:           R   rm              /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
00:06.630:           D   rm              ./probe2.txt
00:06.630:           X   touch           /usr/bin/touch
00:06.631:           R   touch           /usr/lib/locale/**
00:06.631:           R   touch           /etc/locale.alias
00:06.631:           R   touch           /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
00:06.631:           WA  touch           ./subshell.txt
00:06.632-00:06.660: X   mkdir           /usr/bin/mkdir
00:06.632-00:06.661: R   mkdir           /proc/filesystems
00:06.632-00:06.661: R   mkdir           /usr/lib/locale/**
00:06.632-00:06.661: R   mkdir           /etc/locale.alias
00:06.632-00:06.661: R   mkdir           /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
00:06.633:           W   mkdir           ./sub
00:06.634:           r   cat             ./sub/missing.txt
00:06.635-00:06.740: X   python3         /usr/bin/python3.12
00:06.635-00:06.759: R   python3         /usr/**
00:06.635-00:06.741: R   python3         /etc/locale.alias
00:06.649:           d   python3         ./sub/gone
00:06.652-00:06.662: X   chmod           /usr/bin/chmod
00:06.653-00:06.662: R   chmod           /usr/lib/locale/**
00:06.653-00:06.662: R   chmod           /etc/locale.alias
00:06.653-00:06.662: R   chmod           /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
00:06.653:           a!  chmod           ./root-owned.txt
00:06.653:           W   chmod           /dev/null
00:06.654:           X   chown           /usr/bin/chown
00:06.655:           R   chown           /usr/lib/locale/**
00:06.655:           R   chown           /etc/**
00:06.655:           R   chown           /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
00:06.655:           a!  chown           ./root-owned.txt
00:06.655:           W   chown           /dev/null
00:06.657:           w!  mkdir           ./root-owned/x
00:06.657-00:06.660: W   mkdir           /dev/null
00:06.658:           w!  mkdir           /usr/local/buildcage-ro-probe
00:06.661:           W   mkdir           ./A
00:06.661:           W   bash            ./A/run.sh
00:06.662:           A   chmod           ./A/run.sh
00:06.663:           X   run.sh          ./A/run.sh
00:06.664:           W   bash            ./mapped.bin
00:06.678:           R   python3         ./mapped.bin
00:06.681:           W   bash            ./ro-mapped.bin
00:06.699:           X   mkfifo          /usr/bin/mkfifo
00:06.700:           R   mkfifo          /proc/filesystems
00:06.700:           R   mkfifo          /usr/lib/locale/**
00:06.700:           R   mkfifo          /etc/locale.alias
00:06.700:           R   mkfifo          /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
00:06.700:           W   mkfifo          ./fifo
00:06.715:           w   python3         ./fifo
00:06.718:           W   bash            ./mprotected.bin
00:06.718:           W   bash            ./mprotected-rwx.bin
00:06.737:           RW  python3         ./mprotected.bin
00:06.737:           RW  python3         ./mprotected-rwx.bin
00:06.759:           W   python3         memfd:"probe-memfd"
00:06.759:           WDA python3         ./gone-bin
00:06.760-00:06.761: R   python3         /proc/<pid>/stat
00:06.760:           X   memfd:probe-mem memfd:"probe-memfd"
00:06.762:           X   gone-bin        ./gone-bin (deleted)
00:06.766:           W   bash            ./shared.txt
00:06.767:           X   sh              /usr/bin/dash
00:06.767:           W   sh              ./shared.txt
00:06.768:           W   bash            ./execd.txt
00:06.769:           W   cat             ./execd.txt
00:06.769:           X   true            /usr/bin/true
00:06.769-00:06.770: R   true            /usr/lib/locale/**
00:06.769:           R   true            /etc/locale.alias
00:06.770:           R   true            /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
00:06.771:           X   uname           /usr/bin/uname
00:06.771:           R   uname           /usr/lib/locale/**
00:06.771:           R   uname           /etc/locale.alias
00:06.771:           R   uname           /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
00:06.772:           X   int80           ./int80
```

</details>
