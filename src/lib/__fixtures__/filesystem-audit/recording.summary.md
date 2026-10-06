### Filesystem audit

<sub>first-last access · R read · W write · X exec · M move · D delete · A attr · lowercase = failed · ! = denied</sub>

```
14:09:36.394Z-14:09:36.395Z: R bash /usr/lib/x86_64-linux-gnu/**
14:09:36.394Z:               r bash /dev/tty
14:09:36.394Z-14:09:36.395Z: R bash /usr/lib/locale/**
14:09:36.394Z:               R bash /etc/locale.alias
14:09:36.395Z:               W bash /dev/null
14:09:36.395Z:               X cat  /usr/bin/cat
14:09:36.395Z:               R cat  /etc/**
14:09:36.395Z:               R cat  /usr/lib/locale/**
14:09:36.395Z:               R cat  /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
14:09:36.395Z:               W cat  /dev/null
14:09:36.395Z:               W bash ./probe.txt
14:09:36.395Z:               X mv   /usr/bin/mv
14:09:36.395Z:               R mv   /usr/lib/x86_64-linux-gnu/**
14:09:36.395Z:               R mv   /proc/filesystems
14:09:36.395Z:               R mv   /usr/lib/locale/**
14:09:36.395Z:               R mv   /etc/locale.alias
14:09:36.395Z:               M mv   ./probe.txt
14:09:36.395Z:               X rm   /usr/bin/rm
14:09:36.395Z:               R rm   /usr/lib/locale/**
14:09:36.395Z:               R rm   /etc/locale.alias
14:09:36.395Z:               R rm   /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
14:09:36.395Z:               D rm   ./probe2.txt
```
