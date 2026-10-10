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
| `/usr/bin/chown` |
| `./A/run.sh` |
| `/usr/bin/mkfifo` |
| `memfd:"probe-memfd"` |
| `./gone-bin` (deleted) |
| `/usr/bin/dash` |
| `/usr/bin/true` |
| `/usr/bin/uname` |
| `./int80` |

#### Accessed paths

| Access | Path |
| --- | --- |
| WXA | `./A/run.sh` |
| W | `./execd.txt` |
| W | `./fifo` |
| WDA | `./gone-bin` |
| X | `./gone-bin` (deleted) |
| X | `./int80` |
| RW | `./mapped.bin` |
| RW | `./mprotected-rwx.bin` |
| RW | `./mprotected.bin` |
| WM | `./probe.txt` |
| D | `./probe2.txt` |
| W | `./ro-mapped.bin` |
| a! | `./root-owned.txt` |
| w! | `./root-owned/x` |
| W | `./shared.txt` |
| W | `./sub` |
| d | `./sub/gone` |
| r | `./sub/missing.txt` |
| WA | `./subshell.txt` |
| W | `/dev/null` |
| rw | `/dev/tty` |
| R | `/etc/**` |
| R | `/proc/<pid>/stat` |
| R | `/proc/filesystems` |
| RXw! | `/usr/**` |
| WX | `memfd:"probe-memfd"` |

<details>
<summary>📂 Filesystem details</summary>

<sub>first-last access since the proxy started · flags · command · path</sub>

```
00:06.625:           rw   bash            /dev/tty
00:06.625:           R    bash            /usr/lib/locale/**
00:06.625:           R    bash            /etc/locale.alias
00:06.625:           R    bash            /usr/lib/x86_64-linux-gnu/**
00:06.626-00:06.659: W    bash            /dev/null
00:06.626-00:06.768: X    cat             /usr/bin/cat
00:06.626-00:06.769: R    cat             /usr/lib/locale/**
00:06.626-00:06.769: R    cat             /etc/**
00:06.626-00:06.768: R    cat             /usr/lib/x86_64-linux-gnu/**
00:06.627-00:06.634: W    cat             /dev/null
00:06.627:           W    bash            ./probe.txt
00:06.627:           X    mv              /usr/bin/mv
00:06.628:           R    mv              /proc/filesystems
00:06.628:           R    mv              /usr/lib/locale/**
00:06.628:           R    mv              /etc/locale.alias
00:06.628:           R    mv              /usr/lib/x86_64-linux-gnu/**
00:06.628:           M    mv              ./probe.txt
00:06.629:           X    rm              /usr/bin/rm
00:06.629-00:06.630: R    rm              /usr/lib/locale/**
00:06.629:           R    rm              /etc/locale.alias
00:06.629:           R    rm              /usr/lib/x86_64-linux-gnu/**
00:06.630:           D    rm              ./probe2.txt
00:06.630:           X    touch           /usr/bin/touch
00:06.631:           R    touch           /usr/lib/locale/**
00:06.631:           R    touch           /etc/locale.alias
00:06.631:           R    touch           /usr/lib/x86_64-linux-gnu/**
00:06.631:           WA   touch           ./subshell.txt
00:06.632-00:06.661: RXw! mkdir           /usr/**
00:06.632-00:06.661: R    mkdir           /proc/filesystems
00:06.632-00:06.661: R    mkdir           /etc/locale.alias
00:06.633:           W    mkdir           ./sub
00:06.634:           r    cat             ./sub/missing.txt
00:06.635-00:06.759: RX   python3         /usr/**
00:06.635-00:06.741: R    python3         /etc/locale.alias
00:06.649:           d    python3         ./sub/gone
00:06.652-00:06.662: X    chmod           /usr/bin/chmod
00:06.653-00:06.662: R    chmod           /usr/lib/locale/**
00:06.653-00:06.662: R    chmod           /etc/locale.alias
00:06.653-00:06.662: R    chmod           /usr/lib/x86_64-linux-gnu/**
00:06.653:           a!   chmod           ./root-owned.txt
00:06.653:           W    chmod           /dev/null
00:06.654:           X    chown           /usr/bin/chown
00:06.655:           R    chown           /usr/lib/locale/**
00:06.655:           R    chown           /etc/**
00:06.655:           R    chown           /usr/lib/x86_64-linux-gnu/**
00:06.655:           a!   chown           ./root-owned.txt
00:06.655:           W    chown           /dev/null
00:06.657:           w!   mkdir           ./root-owned/x
00:06.657-00:06.660: W    mkdir           /dev/null
00:06.661:           W    mkdir           ./A
00:06.661:           W    bash            ./A/run.sh
00:06.662:           A    chmod           ./A/run.sh
00:06.663:           X    run.sh          ./A/run.sh
00:06.664:           W    bash            ./mapped.bin
00:06.678:           R    python3         ./mapped.bin
00:06.681:           W    bash            ./ro-mapped.bin
00:06.699:           X    mkfifo          /usr/bin/mkfifo
00:06.700:           R    mkfifo          /proc/filesystems
00:06.700:           R    mkfifo          /usr/lib/locale/**
00:06.700:           R    mkfifo          /etc/locale.alias
00:06.700:           R    mkfifo          /usr/lib/x86_64-linux-gnu/**
00:06.700:           W    mkfifo          ./fifo
00:06.715:           w    python3         ./fifo
00:06.718:           W    bash            ./mprotected.bin
00:06.718:           W    bash            ./mprotected-rwx.bin
00:06.737:           RW   python3         ./mprotected.bin
00:06.737:           RW   python3         ./mprotected-rwx.bin
00:06.759:           W    python3         memfd:"probe-memfd"
00:06.759:           WDA  python3         ./gone-bin
00:06.760-00:06.761: R    python3         /proc/<pid>/stat
00:06.760:           X    memfd:probe-mem memfd:"probe-memfd"
00:06.762:           X    gone-bin        ./gone-bin (deleted)
00:06.766:           W    bash            ./shared.txt
00:06.767:           X    sh              /usr/bin/dash
00:06.767:           W    sh              ./shared.txt
00:06.768:           W    bash            ./execd.txt
00:06.769:           W    cat             ./execd.txt
00:06.769:           X    true            /usr/bin/true
00:06.769-00:06.770: R    true            /usr/lib/locale/**
00:06.769:           R    true            /etc/locale.alias
00:06.770:           R    true            /usr/lib/x86_64-linux-gnu/**
00:06.771:           X    uname           /usr/bin/uname
00:06.771:           R    uname           /usr/lib/locale/**
00:06.771:           R    uname           /etc/locale.alias
00:06.771:           R    uname           /usr/lib/x86_64-linux-gnu/**
00:06.772:           X    int80           ./int80
```

</details>
