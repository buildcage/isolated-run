### Filesystem audit

<sub>R read · W write · X exec · M move · D delete · A attr · lowercase = failed · ! = denied</sub>

#### Executed

| Path |
| --- |
| `/usr/bin/cat` |
| `/usr/bin/mv` |
| `/usr/bin/rm` |
| `/usr/bin/touch` |
| `/usr/bin/mkdir` |
| `/usr/bin/python3.12` |
| `/usr/bin/chmod` |
| `./A/run.sh` |
| `/usr/bin/true` |

#### Accessed paths

| Access | Path |
| --- | --- |
| WXA | `./A/run.sh` |
| RW | `./mapped.bin` |
| WM | `./probe.txt` |
| D | `./probe2.txt` |
| a! | `./root-owned.txt` |
| w! | `./root-owned/x` |
| W | `./sub` |
| d | `./sub/gone` |
| r | `./sub/missing.txt` |
| WA | `./subshell.txt` |
| W | `/dev/null` |
| r | `/dev/tty` |
| R | `/etc/**` |
| R | `/proc/filesystems` |
| RX | `/usr/**` |

<details>
<summary>📂 Filesystem details</summary>

<sub>first-last access</sub>

```
00:06.468:           r  bash    /dev/tty
00:06.468-00:06.469: R  bash    /usr/lib/locale/**
00:06.468:           R  bash    /etc/locale.alias
00:06.468:           R  bash    /usr/lib/x86_64-linux-gnu/**
00:06.469-00:06.492: W  bash    /dev/null
00:06.469-00:06.475: X  cat     /usr/bin/cat
00:06.469-00:06.476: R  cat     /usr/lib/locale/**
00:06.469-00:06.476: R  cat     /etc/**
00:06.470-00:06.476: R  cat     /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
00:06.470-00:06.476: W  cat     /dev/null
00:06.470:           W  bash    ./probe.txt
00:06.470:           X  mv      /usr/bin/mv
00:06.471:           R  mv      /proc/filesystems
00:06.471:           R  mv      /usr/lib/locale/**
00:06.471:           R  mv      /etc/locale.alias
00:06.471:           R  mv      /usr/lib/x86_64-linux-gnu/**
00:06.471:           M  mv      ./probe.txt
00:06.472:           X  rm      /usr/bin/rm
00:06.472:           R  rm      /usr/lib/locale/**
00:06.472:           R  rm      /etc/locale.alias
00:06.472:           R  rm      /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
00:06.472:           D  rm      ./probe2.txt
00:06.473:           X  touch   /usr/bin/touch
00:06.473:           R  touch   /usr/lib/locale/**
00:06.473:           R  touch   /etc/locale.alias
00:06.473:           R  touch   /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
00:06.473:           WA touch   ./subshell.txt
00:06.474-00:06.493: X  mkdir   /usr/bin/mkdir
00:06.474-00:06.493: R  mkdir   /proc/filesystems
00:06.474-00:06.494: R  mkdir   /usr/lib/locale/**
00:06.474-00:06.494: R  mkdir   /etc/locale.alias
00:06.474-00:06.494: R  mkdir   /usr/lib/x86_64-linux-gnu/**
00:06.475:           W  mkdir   ./sub
00:06.476:           r  cat     ./sub/missing.txt
00:06.477-00:06.507: RX python3 /usr/**
00:06.477-00:06.497: R  python3 /etc/locale.alias
00:06.488:           d  python3 ./sub/gone
00:06.491-00:06.494: X  chmod   /usr/bin/chmod
00:06.491-00:06.495: R  chmod   /usr/lib/locale/**
00:06.491-00:06.495: R  chmod   /etc/locale.alias
00:06.491-00:06.495: R  chmod   /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
00:06.491:           a! chmod   ./root-owned.txt
00:06.492:           W  chmod   /dev/null
00:06.493:           w! mkdir   ./root-owned/x
00:06.493:           W  mkdir   /dev/null
00:06.494:           W  mkdir   ./A
00:06.494:           W  bash    ./A/run.sh
00:06.495:           A  chmod   ./A/run.sh
00:06.495:           X  run.sh  ./A/run.sh
00:06.496:           W  bash    ./mapped.bin
00:06.847:           R  python3 ./mapped.bin
00:06.851:           X  true    /usr/bin/true
00:06.851:           R  true    /usr/lib/locale/**
00:06.851:           R  true    /etc/locale.alias
00:06.851:           R  true    /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
```

</details>
