Keep track of active TCP connections (by talking to the `ip_conntrack` kernel module).

# what

Every call to `c.Connections()` will return all connections active since the last
call to `c.Connections()`. The connections can either still be established, or
have been terminated since the last call. Connections which are established and
teared down in between calls to `c.Connections()` will also be reported.

# install

This is a pure Go lib, but the `ip_conntrack` Linux kernel module must be loaded (`modprobe
ip_conntrack`).

To enable packet/byte counts you need to enable conntrack accounting:

```
echo "1" > /proc/sys/net/netfilter/nf_conntrack_acct
```

# status

seems to work

# todo

ipv6.
