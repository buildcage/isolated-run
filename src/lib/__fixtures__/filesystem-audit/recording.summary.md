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

#### Accessed paths

| Access | Path |
| --- | --- |
| WXA | `./A/run.sh` |
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
00:06.625:           r  bash    /dev/tty
00:06.625-00:06.626: R  bash    /usr/lib/locale/**
00:06.625:           R  bash    /etc/locale.alias
00:06.625:           R  bash    /usr/lib/x86_64-linux-gnu/**
00:06.626-00:06.655: W  bash    /dev/null
00:06.627-00:06.635: X  cat     /usr/bin/cat
00:06.627-00:06.635: R  cat     /usr/lib/locale/**
00:06.627-00:06.635: R  cat     /etc/**
00:06.627-00:06.635: R  cat     /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
00:06.627-00:06.635: W  cat     /dev/null
00:06.628:           W  bash    ./probe.txt
00:06.629:           X  mv      /usr/bin/mv
00:06.629:           R  mv      /proc/filesystems
00:06.629-00:06.630: R  mv      /usr/lib/locale/**
00:06.629:           R  mv      /etc/locale.alias
00:06.629:           R  mv      /usr/lib/x86_64-linux-gnu/**
00:06.630:           M  mv      ./probe.txt
00:06.630:           X  rm      /usr/bin/rm
00:06.631:           R  rm      /usr/lib/locale/**
00:06.631:           R  rm      /etc/locale.alias
00:06.631:           R  rm      /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
00:06.631:           D  rm      ./probe2.txt
00:06.632:           X  touch   /usr/bin/touch
00:06.632:           R  touch   /usr/lib/locale/**
00:06.632:           R  touch   /etc/locale.alias
00:06.632:           R  touch   /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
00:06.632:           WA touch   ./subshell.txt
00:06.633-00:06.656: X  mkdir   /usr/bin/mkdir
00:06.634-00:06.657: R  mkdir   /proc/filesystems
00:06.634-00:06.657: R  mkdir   /usr/lib/locale/**
00:06.634-00:06.657: R  mkdir   /etc/locale.alias
00:06.634-00:06.657: R  mkdir   /usr/lib/x86_64-linux-gnu/**
00:06.634:           W  mkdir   ./sub
00:06.635:           r  cat     ./sub/missing.txt
00:06.636-00:06.650: RX python3 /usr/**
00:06.637:           R  python3 /etc/locale.alias
00:06.650:           d  python3 ./sub/gone
00:06.654-00:06.658: X  chmod   /usr/bin/chmod
00:06.654-00:06.658: R  chmod   /usr/lib/locale/**
00:06.654-00:06.658: R  chmod   /etc/locale.alias
00:06.654-00:06.658: R  chmod   /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
00:06.654:           a! chmod   ./root-owned.txt
00:06.654:           W  chmod   /dev/null
00:06.656:           w! mkdir   ./root-owned/x
00:06.656:           W  mkdir   /dev/null
00:06.657:           W  mkdir   ./A
00:06.657:           W  bash    ./A/run.sh
00:06.658:           A  chmod   ./A/run.sh
00:06.659:           X  run.sh  ./A/run.sh
```

</details>
