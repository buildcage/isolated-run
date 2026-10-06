### Filesystem audit

<sub>R read · W write · X exec · M move · D delete · A attr · lowercase = failed · ! = denied</sub>

```
W bash ./probe.txt
M mv   ./probe.txt
D rm   ./probe2.txt
W bash /dev/null
W cat  /dev/null
r bash /dev/tty
R cat  /etc/**
R bash /etc/locale.alias
R mv   /etc/locale.alias
R rm   /etc/locale.alias
R mv   /proc/filesystems
X cat  /usr/bin/cat
X mv   /usr/bin/mv
X rm   /usr/bin/rm
R bash /usr/lib/locale/**
R cat  /usr/lib/locale/**
R mv   /usr/lib/locale/**
R rm   /usr/lib/locale/**
R bash /usr/lib/x86_64-linux-gnu/**
R mv   /usr/lib/x86_64-linux-gnu/**
R cat  /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
R rm   /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
```
