### Filesystem audit

<sub>first-last access · R read · W write · X exec · M move · D delete · A attr · lowercase = failed · ! = denied</sub>

```
00:06.394:           r bash /dev/tty
00:06.394-00:06.395: R bash /usr/lib/locale/**
00:06.394:           R bash /etc/locale.alias
00:06.394:           R bash /usr/lib/x86_64-linux-gnu/**
00:06.395:           W bash /dev/null
00:06.395:           X cat  /usr/bin/cat
00:06.395:           R cat  /usr/lib/locale/**
00:06.395:           R cat  /etc/**
00:06.395:           R cat  /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
00:06.395:           W cat  /dev/null
00:06.395:           W bash ./probe.txt
00:06.395:           X mv   /usr/bin/mv
00:06.395:           R mv   /proc/filesystems
00:06.395:           R mv   /usr/lib/locale/**
00:06.395:           R mv   /etc/locale.alias
00:06.395:           R mv   /usr/lib/x86_64-linux-gnu/**
00:06.395:           M mv   ./probe.txt
00:06.395:           X rm   /usr/bin/rm
00:06.395:           R rm   /usr/lib/locale/**
00:06.395:           R rm   /etc/locale.alias
00:06.395:           R rm   /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
00:06.395:           D rm   ./probe2.txt
```
