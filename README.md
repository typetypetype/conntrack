Keep track of active TCP connections (using the `conntrack` util).

# what

Every call to `c.Connections()` will return all connections active since the last
call to `c.Connections()`. The connections can either still be established, or
have been terminated since the last call. Connections which are established and
teared down in between calls to `c.Connections()` will also be reported.

Keeps things simple.

# status

proof-of-concept

# todo

ipv6. My `conntrack` has trouble with them, somehow.
