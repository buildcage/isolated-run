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
| `/usr/bin/x86_64-linux-gnu-gcc-13` |
| `/usr/libexec/gcc/x86_64-linux-gnu/13/cc1` |
| `/usr/bin/x86_64-linux-gnu-as` |
| `/usr/libexec/gcc/x86_64-linux-gnu/13/collect2` |
| `/usr/bin/x86_64-linux-gnu-ld.bfd` |
| `./int80` |

#### Accessed paths

| Access | Path |
| --- | --- |
| WXA | `./A/run.sh` |
| W | `./execd.txt` |
| W | `./fifo` |
| WDA | `./gone-bin` |
| X | `./gone-bin` (deleted) |
| RWXA | `./int80` |
| r | `./libgcc_s.so.1` |
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
| RWD | `/tmp/cc27m5U1.s` |
| WD | `/tmp/cc5zO32N.res` |
| WD | `/tmp/ccWk6phl.cdtor.o` |
| RWD | `/tmp/ccY834QW.o` |
| WD | `/tmp/ccYU8EoQ.cdtor.c` |
| RXw! | `/usr/**` |
| WX | `memfd:"probe-memfd"` |

<details>
<summary>📂 Filesystem details</summary>

<sub>first-last access since the proxy started · flags · command · path</sub>

```
00:06.481:           rw   bash            /dev/tty
00:06.481:           R    bash            /usr/lib/locale/**
00:06.481:           R    bash            /etc/locale.alias
00:06.481:           R    bash            /usr/lib/x86_64-linux-gnu/**
00:06.482-00:06.516: W    bash            /dev/null
00:06.482-00:06.654: X    cat             /usr/bin/cat
00:06.483-00:06.654: R    cat             /usr/lib/locale/**
00:06.483-00:06.654: R    cat             /etc/**
00:06.483-00:06.654: R    cat             /usr/lib/x86_64-linux-gnu/**
00:06.483-00:06.491: W    cat             /dev/null
00:06.483:           W    bash            ./probe.txt
00:06.484:           X    mv              /usr/bin/mv
00:06.484:           R    mv              /proc/filesystems
00:06.484-00:06.485: R    mv              /usr/lib/locale/**
00:06.484:           R    mv              /etc/locale.alias
00:06.484:           R    mv              /usr/lib/x86_64-linux-gnu/**
00:06.485:           M    mv              ./probe.txt
00:06.485:           X    rm              /usr/bin/rm
00:06.486:           R    rm              /usr/lib/locale/**
00:06.486:           R    rm              /etc/locale.alias
00:06.486:           R    rm              /usr/lib/x86_64-linux-gnu/**
00:06.486:           D    rm              ./probe2.txt
00:06.487:           X    touch           /usr/bin/touch
00:06.487:           R    touch           /usr/lib/locale/**
00:06.487:           R    touch           /etc/locale.alias
00:06.487:           R    touch           /usr/lib/x86_64-linux-gnu/**
00:06.487:           WA   touch           ./subshell.txt
00:06.488-00:06.518: RXw! mkdir           /usr/**
00:06.489-00:06.518: R    mkdir           /proc/filesystems
00:06.489-00:06.518: R    mkdir           /etc/locale.alias
00:06.489:           W    mkdir           ./sub
00:06.491:           r    cat             ./sub/missing.txt
00:06.491-00:06.644: RX   python3         /usr/**
00:06.492-00:06.625: R    python3         /etc/locale.alias
00:06.505:           d    python3         ./sub/gone
00:06.509-00:06.519: X    chmod           /usr/bin/chmod
00:06.509-00:06.520: R    chmod           /usr/lib/locale/**
00:06.509-00:06.519: R    chmod           /etc/locale.alias
00:06.510-00:06.519: R    chmod           /usr/lib/x86_64-linux-gnu/**
00:06.510:           a!   chmod           ./root-owned.txt
00:06.510:           W    chmod           /dev/null
00:06.511:           X    chown           /usr/bin/chown
00:06.511-00:06.512: R    chown           /usr/lib/locale/**
00:06.511-00:06.512: R    chown           /etc/**
00:06.512:           R    chown           /usr/lib/x86_64-linux-gnu/**
00:06.512:           a!   chown           ./root-owned.txt
00:06.512:           W    chown           /dev/null
00:06.514:           w!   mkdir           ./root-owned/x
00:06.514-00:06.517: W    mkdir           /dev/null
00:06.518:           W    mkdir           ./A
00:06.518:           W    bash            ./A/run.sh
00:06.520:           A    chmod           ./A/run.sh
00:06.520:           X    run.sh          ./A/run.sh
00:06.521:           W    bash            ./mapped.bin
00:06.544:           R    python3         ./mapped.bin
00:06.547:           W    bash            ./ro-mapped.bin
00:06.567:           X    mkfifo          /usr/bin/mkfifo
00:06.568:           R    mkfifo          /proc/filesystems
00:06.568:           R    mkfifo          /usr/lib/locale/**
00:06.568:           R    mkfifo          /etc/locale.alias
00:06.568:           R    mkfifo          /usr/lib/x86_64-linux-gnu/**
00:06.568:           W    mkfifo          ./fifo
00:06.583:           w    python3         ./fifo
00:06.587:           W    bash            ./mprotected.bin
00:06.587:           W    bash            ./mprotected-rwx.bin
00:06.620:           RW   python3         ./mprotected.bin
00:06.620:           RW   python3         ./mprotected-rwx.bin
00:06.644:           W    python3         memfd:"probe-memfd"
00:06.644:           WDA  python3         ./gone-bin
00:06.645-00:06.646: R    python3         /proc/<pid>/stat
00:06.646:           X    memfd:probe-mem memfd:"probe-memfd"
00:06.647:           X    gone-bin        ./gone-bin (deleted)
00:06.652:           W    bash            ./shared.txt
00:06.653:           X    sh              /usr/bin/dash
00:06.653:           W    sh              ./shared.txt
00:06.653-00:06.654: W    bash            ./execd.txt
00:06.654:           W    cat             ./execd.txt
00:06.655:           X    true            /usr/bin/true
00:06.655-00:06.656: R    true            /usr/lib/locale/**
00:06.655:           R    true            /etc/locale.alias
00:06.655:           R    true            /usr/lib/x86_64-linux-gnu/**
00:06.656:           X    uname           /usr/bin/uname
00:06.657:           R    uname           /usr/lib/locale/**
00:06.657:           R    uname           /etc/locale.alias
00:06.657:           R    uname           /usr/lib/x86_64-linux-gnu/**
00:06.659-00:06.661: RX   gcc             /usr/**
00:06.661:           R    gcc             /etc/locale.alias
00:06.664-00:06.755: WD   gcc             /tmp/cc27m5U1.s
00:06.665-00:06.684: RX   cc1             /usr/**
00:06.672:           R    cc1             /etc/locale.alias
00:06.682-00:06.719: W    cc1             /tmp/cc27m5U1.s
00:06.720-00:06.755: WD   gcc             /tmp/ccY834QW.o
00:06.721:           X    as              /usr/bin/x86_64-linux-gnu-as
00:06.722-00:06.723: R    as              /usr/lib/locale/**
00:06.722:           R    as              /etc/locale.alias
00:06.723:           R    as              /usr/lib/x86_64-linux-gnu/**
00:06.723-00:06.726: RW   as              /tmp/ccY834QW.o
00:06.724:           R    as              /tmp/cc27m5U1.s
00:06.727-00:06.755: WD   gcc             /tmp/cc5zO32N.res
00:06.728-00:06.729: RX   collect2        /usr/**
00:06.729:           R    collect2        /etc/locale.alias
00:06.729-00:06.754: WD   collect2        /tmp/ccYU8EoQ.cdtor.c
00:06.729-00:06.754: WD   collect2        /tmp/ccWk6phl.cdtor.o
00:06.730-00:06.749: RX   ld              /usr/**
00:06.733:           R    ld              /etc/locale.alias
00:06.735-00:06.754: RWA  ld              ./int80
00:06.737:           R    ld              /tmp/ccY834QW.o
00:06.741-00:06.748: r    ld              ./libgcc_s.so.1
00:06.756:           X    int80           ./int80
```

</details>
