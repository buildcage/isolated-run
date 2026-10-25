
## Filesystem Activity Report

### 📂 Accessed Paths (89)

<sub>R read · W write · X exec · M move · L link · D delete · A attr · lowercase = failed · ! = refused</sub>

| Program | Command | Access | Path |
| --- | --- | --- | --- |
| `bash` | `bash` | WX | `./A/run.sh` |
| `bash` | `bash` | W | `./execd.txt` |
| `bash` | `bash` | X | `./int80` |
| `bash` | `bash` | W | `./mapped.bin` |
| `bash` | `bash` | W | `./mprotected-rwx.bin` |
| `bash` | `bash` | W | `./mprotected.bin` |
| `bash` | `bash` | W | `./probe.txt` |
| `bash` | `bash` | W | `./ro-mapped.bin` |
| `bash` | `bash` | W | `./shared.txt` |
| `bash` | `bash` | W | `/dev/null` |
| `bash` | `bash` | rw | `/dev/tty` |
| `bash` | `bash` | R | `/etc/locale.alias` |
| `bash` | `bash` | X | `/usr/bin/cat` |
| `bash` | `bash` | X | `/usr/bin/chmod` |
| `bash` | `bash` | X | `/usr/bin/chown` |
| `bash` | `bash` | X | `/usr/bin/dash` |
| `bash` | `bash` | X | `/usr/bin/mkdir` |
| `bash` | `bash` | X | `/usr/bin/mkfifo` |
| `bash` | `bash` | X | `/usr/bin/mv` |
| `bash` | `bash` | X | `/usr/bin/python3.12` |
| `bash` | `bash` | X | `/usr/bin/rm` |
| `bash` | `bash` | X | `/usr/bin/touch` |
| `bash` | `bash` | X | `/usr/bin/true` |
| `bash` | `bash` | X | `/usr/bin/uname` |
| `bash` | `bash` | R | `/usr/lib/locale/**` |
| `bash` | `bash` | R | `/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache` |
| `/usr/bin/cat` | `cat` | W | `./execd.txt` |
| `/usr/bin/cat` | `cat` | r | `./sub/missing.txt` |
| `/usr/bin/cat` | `cat` | W | `/dev/null` |
| `/usr/bin/cat` | `cat` | R | `/etc/hostname` |
| `/usr/bin/cat` | `cat` | R | `/etc/locale.alias` |
| `/usr/bin/cat` | `cat` | R | `/usr/lib/locale/**` |
| `/usr/bin/cat` | `cat` | R | `/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache` |
| `/usr/bin/mv` | `mv` | M | `./probe.txt` |
| `/usr/bin/mv` | `mv` | R | `/etc/locale.alias` |
| `/usr/bin/mv` | `mv` | R | `/proc/filesystems` |
| `/usr/bin/mv` | `mv` | R | `/usr/lib/locale/**` |
| `/usr/bin/mv` | `mv` | R | `/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache` |
| `/usr/bin/rm` | `rm` | D | `./probe2.txt` |
| `/usr/bin/rm` | `rm` | R | `/etc/locale.alias` |
| `/usr/bin/rm` | `rm` | R | `/usr/lib/locale/**` |
| `/usr/bin/rm` | `rm` | R | `/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache` |
| `/usr/bin/touch` | `touch` | WA | `./subshell.txt` |
| `/usr/bin/touch` | `touch` | R | `/etc/locale.alias` |
| `/usr/bin/touch` | `touch` | R | `/usr/lib/locale/**` |
| `/usr/bin/touch` | `touch` | R | `/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache` |
| `/usr/bin/mkdir` | `mkdir` | W | `./A` |
| `/usr/bin/mkdir` | `mkdir` | w! | `./root-owned/x` |
| `/usr/bin/mkdir` | `mkdir` | W | `./sub` |
| `/usr/bin/mkdir` | `mkdir` | W | `/dev/null` |
| `/usr/bin/mkdir` | `mkdir` | R | `/etc/locale.alias` |
| `/usr/bin/mkdir` | `mkdir` | R | `/proc/filesystems` |
| `/usr/bin/mkdir` | `mkdir` | R | `/usr/lib/locale/**` |
| `/usr/bin/mkdir` | `mkdir` | R | `/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache` |
| `/usr/bin/mkdir` | `mkdir` | w! | `/usr/local/buildcage-ro-probe` |
| `/usr/bin/python3.12` | `python3.12` | w | `./fifo` |
| `/usr/bin/python3.12` | `python3.12` | WDA | `./gone-bin` |
| `/usr/bin/python3.12` | `python3.12` | X | `./gone-bin` (deleted) |
| `/usr/bin/python3.12` | `python3.12` | R | `./mapped.bin` |
| `/usr/bin/python3.12` | `python3.12` | RW | `./mprotected-rwx.bin` |
| `/usr/bin/python3.12` | `python3.12` | RW | `./mprotected.bin` |
| `/usr/bin/python3.12` | `python3.12` | d | `./sub/gone` |
| `/usr/bin/python3.12` | `python3.12` | R | `/etc/locale.alias` |
| `/usr/bin/python3.12` | `python3.12` | R | `/proc/<pid>/stat` |
| `/usr/bin/python3.12` | `python3.12` | R | `/usr/**` |
| `/usr/bin/python3.12` | `python3.12` | WX | `memfd:"probe-memfd"` |
| `/usr/bin/chmod` | `chmod` | A | `./A/run.sh` |
| `/usr/bin/chmod` | `chmod` | a! | `./root-owned.txt` |
| `/usr/bin/chmod` | `chmod` | W | `/dev/null` |
| `/usr/bin/chmod` | `chmod` | R | `/etc/locale.alias` |
| `/usr/bin/chmod` | `chmod` | R | `/usr/lib/locale/**` |
| `/usr/bin/chmod` | `chmod` | R | `/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache` |
| `/usr/bin/chown` | `chown` | a! | `./root-owned.txt` |
| `/usr/bin/chown` | `chown` | W | `/dev/null` |
| `/usr/bin/chown` | `chown` | R | `/etc/**` |
| `/usr/bin/chown` | `chown` | R | `/usr/lib/locale/**` |
| `/usr/bin/chown` | `chown` | R | `/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache` |
| `/usr/bin/mkfifo` | `mkfifo` | W | `./fifo` |
| `/usr/bin/mkfifo` | `mkfifo` | R | `/etc/locale.alias` |
| `/usr/bin/mkfifo` | `mkfifo` | R | `/proc/filesystems` |
| `/usr/bin/mkfifo` | `mkfifo` | R | `/usr/lib/locale/**` |
| `/usr/bin/mkfifo` | `mkfifo` | R | `/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache` |
| `/usr/bin/dash` | `dash` | W | `./shared.txt` |
| `/usr/bin/true` | `true` | R | `/etc/locale.alias` |
| `/usr/bin/true` | `true` | R | `/usr/lib/locale/**` |
| `/usr/bin/true` | `true` | R | `/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache` |
| `/usr/bin/uname` | `uname` | R | `/etc/locale.alias` |
| `/usr/bin/uname` | `uname` | R | `/usr/lib/locale/**` |
| `/usr/bin/uname` | `uname` | R | `/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache` |

<details>
<summary>🔍 File access details</summary>

<sub>first-last access since the proxy started · flags · command · path</sub>

```
00:06.625:           rw  bash       /dev/tty
00:06.625:           R   bash       /usr/lib/locale/**
00:06.625:           R   bash       /etc/locale.alias
00:06.625:           R   bash       /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
00:06.626-00:06.659: W   bash       /dev/null
00:06.626-00:06.768: X   bash       /usr/bin/cat
00:06.626-00:06.769: R   cat        /usr/lib/locale/**
00:06.626-00:06.768: R   cat        /etc/locale.alias
00:06.626-00:06.768: R   cat        /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
00:06.627-00:06.769: R   cat        /etc/hostname
00:06.627-00:06.634: W   cat        /dev/null
00:06.627:           W   bash       ./probe.txt
00:06.627:           X   bash       /usr/bin/mv
00:06.628:           R   mv         /proc/filesystems
00:06.628:           R   mv         /usr/lib/locale/**
00:06.628:           R   mv         /etc/locale.alias
00:06.628:           R   mv         /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
00:06.628:           M   mv         ./probe.txt
00:06.629:           X   bash       /usr/bin/rm
00:06.629-00:06.630: R   rm         /usr/lib/locale/**
00:06.629:           R   rm         /etc/locale.alias
00:06.629:           R   rm         /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
00:06.630:           D   rm         ./probe2.txt
00:06.630:           X   bash       /usr/bin/touch
00:06.631:           R   touch      /usr/lib/locale/**
00:06.631:           R   touch      /etc/locale.alias
00:06.631:           R   touch      /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
00:06.631:           WA  touch      ./subshell.txt
00:06.632-00:06.660: X   bash       /usr/bin/mkdir
00:06.632-00:06.661: R   mkdir      /proc/filesystems
00:06.632-00:06.661: R   mkdir      /usr/lib/locale/**
00:06.632-00:06.661: R   mkdir      /etc/locale.alias
00:06.632-00:06.661: R   mkdir      /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
00:06.633:           W   mkdir      ./sub
00:06.634:           r   cat        ./sub/missing.txt
00:06.635-00:06.740: X   bash       /usr/bin/python3.12
00:06.635-00:06.759: R   python3.12 /usr/**
00:06.635-00:06.741: R   python3.12 /etc/locale.alias
00:06.649:           d   python3.12 ./sub/gone
00:06.652-00:06.662: X   bash       /usr/bin/chmod
00:06.653-00:06.662: R   chmod      /usr/lib/locale/**
00:06.653-00:06.662: R   chmod      /etc/locale.alias
00:06.653-00:06.662: R   chmod      /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
00:06.653:           a!  chmod      ./root-owned.txt
00:06.653:           W   chmod      /dev/null
00:06.654:           X   bash       /usr/bin/chown
00:06.655:           R   chown      /usr/lib/locale/**
00:06.655:           R   chown      /etc/**
00:06.655:           R   chown      /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
00:06.655:           a!  chown      ./root-owned.txt
00:06.655:           W   chown      /dev/null
00:06.657:           w!  mkdir      ./root-owned/x
00:06.657-00:06.660: W   mkdir      /dev/null
00:06.658:           w!  mkdir      /usr/local/buildcage-ro-probe
00:06.661:           W   mkdir      ./A
00:06.661-00:06.663: WX  bash       ./A/run.sh
00:06.662:           A   chmod      ./A/run.sh
00:06.664:           W   bash       ./mapped.bin
00:06.678:           R   python3.12 ./mapped.bin
00:06.681:           W   bash       ./ro-mapped.bin
00:06.699:           X   bash       /usr/bin/mkfifo
00:06.700:           R   mkfifo     /proc/filesystems
00:06.700:           R   mkfifo     /usr/lib/locale/**
00:06.700:           R   mkfifo     /etc/locale.alias
00:06.700:           R   mkfifo     /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
00:06.700:           W   mkfifo     ./fifo
00:06.715:           w   python3.12 ./fifo
00:06.718:           W   bash       ./mprotected.bin
00:06.718:           W   bash       ./mprotected-rwx.bin
00:06.737:           RW  python3.12 ./mprotected.bin
00:06.737:           RW  python3.12 ./mprotected-rwx.bin
00:06.759-00:06.760: WX  python3.12 memfd:"probe-memfd"
00:06.759:           WDA python3.12 ./gone-bin
00:06.760-00:06.761: R   python3.12 /proc/<pid>/stat
00:06.762:           X   python3.12 ./gone-bin (deleted)
00:06.766:           W   bash       ./shared.txt
00:06.767:           X   bash       /usr/bin/dash
00:06.767:           W   dash       ./shared.txt
00:06.768:           W   bash       ./execd.txt
00:06.769:           W   cat        ./execd.txt
00:06.769:           X   bash       /usr/bin/true
00:06.769-00:06.770: R   true       /usr/lib/locale/**
00:06.769:           R   true       /etc/locale.alias
00:06.770:           R   true       /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
00:06.771:           X   bash       /usr/bin/uname
00:06.771:           R   uname      /usr/lib/locale/**
00:06.771:           R   uname      /etc/locale.alias
00:06.771:           R   uname      /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
00:06.772:           X   bash       ./int80
```

</details>
