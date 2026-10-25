
## Filesystem Activity Report

> 🚫 Killed for a 32-bit system call: `int80`.

### 📂 Accessed Paths (114)

<sub>R read · W write · X exec · M move · L link · D delete · A attr · lowercase = failed · ! = refused</sub>

| Program | Command | Access | Path |
| --- | --- | --- | --- |
| `bash` | `bash` | WX | `./A/run.sh` |
| `bash` | `bash` | W | `./execd.txt` |
| `bash` | `bash` | W | `./fd-truncate.txt` |
| `bash` | `bash` | W | `./fd-xattr.txt` |
| `bash` | `bash` | X | `./int80` |
| `bash` | `bash` | W | `./link-src.txt` |
| `bash` | `bash` | W | `./mapped.bin` |
| `bash` | `bash` | W | `./mprotected-rwx.bin` |
| `bash` | `bash` | W | `./mprotected.bin` |
| `bash` | `bash` | W | `./probe.txt` |
| `bash` | `bash` | W | `./ro-mapped.bin` |
| `bash` | `bash` | W | `./shared.txt` |
| `bash` | `bash` | r | `./sub/missing.txt` |
| `bash` | `bash` | W | `/dev/null` |
| `bash` | `bash` | rw | `/dev/tty` |
| `bash` | `bash` | R | `/etc/locale.alias` |
| `bash` | `bash` | X | `/usr/bin/cat` |
| `bash` | `bash` | X | `/usr/bin/chmod` |
| `bash` | `bash` | X | `/usr/bin/chown` |
| `bash` | `bash` | X | `/usr/bin/dash` |
| `bash` | `bash` | X | `/usr/bin/ln` |
| `bash` | `bash` | X | `/usr/bin/mkdir` |
| `bash` | `bash` | X | `/usr/bin/mkfifo` |
| `bash` | `bash` | X | `/usr/bin/mv` |
| `bash` | `bash` | X | `/usr/bin/python3.12` |
| `bash` | `bash` | X | `/usr/bin/rm` |
| `bash` | `bash` | X | `/usr/bin/seq` |
| `bash` | `bash` | X | `/usr/bin/touch` |
| `bash` | `bash` | X | `/usr/bin/true` |
| `bash` | `bash` | X | `/usr/bin/uname` |
| `bash` | `bash` | R | `/usr/lib/locale/**` |
| `bash` | `bash` | R | `/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache` |
| `/usr/bin/cat` | `cat` | W | `./execd.txt` |
| `/usr/bin/cat` | `cat` | W | `/dev/null` |
| `/usr/bin/cat` | `cat` | R | `/etc/hostname` |
| `/usr/bin/cat` | `cat` | R | `/etc/locale.alias` |
| `/usr/bin/cat` | `cat` | R | `/proc/<pid>/stat` |
| `/usr/bin/cat` | `cat` | R | `/proc/self/status` |
| `/usr/bin/cat` | `cat` | R | `/usr/lib/locale/**` |
| `/usr/bin/cat` | `cat` | R | `/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache` |
| `/usr/bin/mv` | `mv` | M | `./probe.txt` |
| `/usr/bin/mv` | `mv` | W | `./probe2.txt` |
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
| `/usr/bin/python3.12` | `python3.12` | WA | `./empty-name.txt` |
| `/usr/bin/python3.12` | `python3.12` | w | `./fd-truncate.txt` |
| `/usr/bin/python3.12` | `python3.12` | A | `./fd-xattr.txt` |
| `/usr/bin/python3.12` | `python3.12` | w | `./fifo` |
| `/usr/bin/python3.12` | `python3.12` | WA | `./futimens.txt` |
| `/usr/bin/python3.12` | `python3.12` | WDA | `./gone-bin` |
| `/usr/bin/python3.12` | `python3.12` | X | `./gone-bin` (deleted) |
| `/usr/bin/python3.12` | `python3.12` | R | `./mapped.bin` |
| `/usr/bin/python3.12` | `python3.12` | RW | `./mprotected-rwx.bin` |
| `/usr/bin/python3.12` | `python3.12` | RW | `./mprotected.bin` |
| `/usr/bin/python3.12` | `python3.12` | r | `./sub/absent` |
| `/usr/bin/python3.12` | `python3.12` | d | `./sub/gone` |
| `/usr/bin/python3.12` | `python3.12` | R | `/etc/locale.alias` |
| `/usr/bin/python3.12` | `python3.12` | R | `/proc/self/stat` |
| `/usr/bin/python3.12` | `python3.12` | Ra! | `/usr/**` |
| `/usr/bin/python3.12` | `python3.12` | WX | `memfd:"probe-memfd"` |
| `/usr/bin/mkdir` | `mkdir` | W | `./A` |
| `/usr/bin/mkdir` | `mkdir` | w! | `./root-owned/x` |
| `/usr/bin/mkdir` | `mkdir` | W | `./sub` |
| `/usr/bin/mkdir` | `mkdir` | W | `/dev/null` |
| `/usr/bin/mkdir` | `mkdir` | R | `/etc/locale.alias` |
| `/usr/bin/mkdir` | `mkdir` | R | `/proc/filesystems` |
| `/usr/bin/mkdir` | `mkdir` | R | `/usr/lib/locale/**` |
| `/usr/bin/mkdir` | `mkdir` | R | `/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache` |
| `/usr/bin/mkdir` | `mkdir` | w! | `/usr/local/buildcage-ro-probe` |
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
| `/usr/bin/ln` | `ln` | w | `./hostname-link` |
| `/usr/bin/ln` | `ln` | W | `./link-dst.txt` |
| `/usr/bin/ln` | `ln` | L | `./link-src.txt` |
| `/usr/bin/ln` | `ln` | W | `./long-link` |
| `/usr/bin/ln` | `ln` | W | `/dev/null` |
| `/usr/bin/ln` | `ln` | l | `/etc/hostname` |
| `/usr/bin/ln` | `ln` | R | `/etc/locale.alias` |
| `/usr/bin/ln` | `ln` | R | `/usr/lib/locale/**` |
| `/usr/bin/ln` | `ln` | R | `/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache` |
| `/usr/bin/seq` | `seq` | R | `/etc/locale.alias` |
| `/usr/bin/seq` | `seq` | R | `/usr/lib/locale/**` |
| `/usr/bin/seq` | `seq` | R | `/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache` |
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
00:06.541:           rw  bash       /dev/tty
00:06.541:           R   bash       /usr/lib/locale/**
00:06.541:           R   bash       /etc/locale.alias
00:06.541:           R   bash       /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
00:06.542-00:06.637: W   bash       /dev/null
00:06.542-00:06.742: X   bash       /usr/bin/cat
00:06.542-00:06.743: R   cat        /usr/lib/locale/**
00:06.542-00:06.743: R   cat        /etc/locale.alias
00:06.542-00:06.743: R   cat        /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
00:06.543-00:06.743: R   cat        /etc/hostname
00:06.543-00:06.544: W   cat        /dev/null
00:06.544:           R   cat        /proc/self/status
00:06.544:           R   cat        /proc/<pid>/stat
00:06.544:           W   bash       ./probe.txt
00:06.544:           X   bash       /usr/bin/mv
00:06.545:           R   mv         /proc/filesystems
00:06.545:           R   mv         /usr/lib/locale/**
00:06.545:           R   mv         /etc/locale.alias
00:06.545:           R   mv         /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
00:06.545:           M   mv         ./probe.txt
00:06.545:           W   mv         ./probe2.txt
00:06.546:           X   bash       /usr/bin/rm
00:06.546-00:06.547: R   rm         /usr/lib/locale/**
00:06.546:           R   rm         /etc/locale.alias
00:06.546:           R   rm         /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
00:06.547:           D   rm         ./probe2.txt
00:06.547:           X   bash       /usr/bin/touch
00:06.548:           R   touch      /usr/lib/locale/**
00:06.548:           R   touch      /etc/locale.alias
00:06.548:           R   touch      /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
00:06.548:           WA  touch      ./subshell.txt
00:06.549-00:06.745: X   bash       /usr/bin/python3.12
00:06.549-00:06.759: Ra! python3.12 /usr/**
00:06.549-00:06.745: R   python3.12 /etc/locale.alias
00:06.563:           WA  python3.12 ./futimens.txt
00:06.583:           WA  python3.12 ./empty-name.txt
00:06.587-00:06.632: X   bash       /usr/bin/mkdir
00:06.587-00:06.633: R   mkdir      /proc/filesystems
00:06.587-00:06.633: R   mkdir      /usr/lib/locale/**
00:06.587-00:06.633: R   mkdir      /etc/locale.alias
00:06.587-00:06.633: R   mkdir      /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
00:06.587:           W   mkdir      ./sub
00:06.588:           r   bash       ./sub/missing.txt
00:06.602:           d   python3.12 ./sub/gone
00:06.602:           r   python3.12 ./sub/absent
00:06.606-00:06.634: X   bash       /usr/bin/chmod
00:06.606-00:06.634: R   chmod      /usr/lib/locale/**
00:06.606-00:06.634: R   chmod      /etc/locale.alias
00:06.606-00:06.634: R   chmod      /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
00:06.606:           a!  chmod      ./root-owned.txt
00:06.606:           W   chmod      /dev/null
00:06.607:           X   bash       /usr/bin/chown
00:06.608:           R   chown      /usr/lib/locale/**
00:06.608:           R   chown      /etc/**
00:06.608:           R   chown      /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
00:06.608:           a!  chown      ./root-owned.txt
00:06.608:           W   chown      /dev/null
00:06.610:           w!  mkdir      ./root-owned/x
00:06.610-00:06.632: W   mkdir      /dev/null
00:06.611:           w!  mkdir      /usr/local/buildcage-ro-probe
00:06.611:           W   bash       ./fd-truncate.txt
00:06.612:           W   bash       ./fd-xattr.txt
00:06.627:           w   python3.12 ./fd-truncate.txt
00:06.627:           A   python3.12 ./fd-xattr.txt
00:06.633:           W   mkdir      ./A
00:06.633-00:06.635: WX  bash       ./A/run.sh
00:06.634:           A   chmod      ./A/run.sh
00:06.636:           W   bash       ./link-src.txt
00:06.636-00:06.642: X   bash       /usr/bin/ln
00:06.636-00:06.642: R   ln         /usr/lib/locale/**
00:06.636-00:06.642: R   ln         /etc/locale.alias
00:06.636-00:06.642: R   ln         /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
00:06.637:           W   ln         ./link-dst.txt
00:06.637:           L   ln         ./link-src.txt
00:06.638:           w   ln         ./hostname-link
00:06.638:           l   ln         /etc/hostname
00:06.638:           W   ln         /dev/null
00:06.639:           X   bash       /usr/bin/seq
00:06.639-00:06.640: R   seq        /usr/lib/locale/**
00:06.639:           R   seq        /etc/locale.alias
00:06.640:           R   seq        /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
00:06.642:           W   ln         ./long-link
00:06.642:           W   bash       ./mapped.bin
00:06.657:           R   python3.12 ./mapped.bin
00:06.660:           W   bash       ./ro-mapped.bin
00:06.678:           X   bash       /usr/bin/mkfifo
00:06.678:           R   mkfifo     /proc/filesystems
00:06.678:           R   mkfifo     /usr/lib/locale/**
00:06.678:           R   mkfifo     /etc/locale.alias
00:06.678:           R   mkfifo     /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
00:06.678:           W   mkfifo     ./fifo
00:06.692:           w   python3.12 ./fifo
00:06.695:           W   bash       ./mprotected.bin
00:06.695:           W   bash       ./mprotected-rwx.bin
00:06.711:           RW  python3.12 ./mprotected.bin
00:06.711:           RW  python3.12 ./mprotected-rwx.bin
00:06.734-00:06.735: WX  python3.12 memfd:"probe-memfd"
00:06.734:           WDA python3.12 ./gone-bin
00:06.734-00:06.735: R   python3.12 /proc/self/stat
00:06.736:           X   python3.12 ./gone-bin (deleted)
00:06.741:           W   bash       ./shared.txt
00:06.741:           X   bash       /usr/bin/dash
00:06.742:           W   dash       ./shared.txt
00:06.742:           W   bash       ./execd.txt
00:06.743:           W   cat        ./execd.txt
00:06.744:           X   bash       /usr/bin/true
00:06.744:           R   true       /usr/lib/locale/**
00:06.744:           R   true       /etc/locale.alias
00:06.744:           R   true       /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
00:06.763:           X   bash       /usr/bin/uname
00:06.764:           R   uname      /usr/lib/locale/**
00:06.764:           R   uname      /etc/locale.alias
00:06.764:           R   uname      /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
00:06.765:           X   bash       ./int80
00:06.765:           !   int80      syscall:32-bit getpid (killed)
```

</details>
