#!/bin/sh
# Checks `make install-lib` the way a consumer meets it: the library, its soname link and development link, the
# headers, the scenario corpus and mod-host-protocol.pc, installed with no source tree in reach. A program built
# from `pkg-config --cflags --libs mod-host-protocol` alone must compile against every header and link and run.
# A DESTDIR install must leave DESTDIR out of the .pc file, and `make install` must not install the library.
# Run from the top of the tree after `make lib`: sh .github/scripts/install-lib-check.sh
set -eu

CC=${CC:-cc}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fail() { echo "install-lib: $*" >&2; exit 1; }

# a plain install under a prefix of its own
prefix=$work/prefix
make -s install-lib PREFIX="$prefix" >/dev/null
lib=$prefix/lib
[ -f "$lib/libmod-host-protocol.so.0.1.0" ] && [ ! -L "$lib/libmod-host-protocol.so.0.1.0" ] \
    || fail "no libmod-host-protocol.so.0.1.0"
[ "$(readlink "$lib/libmod-host-protocol.so.0")" = libmod-host-protocol.so.0.1.0 ] || fail "soname link is wrong"
[ "$(readlink "$lib/libmod-host-protocol.so")" = libmod-host-protocol.so.0 ] || fail "development link is wrong"
readelf -d "$lib/libmod-host-protocol.so.0.1.0" | grep -q 'SONAME.*\[libmod-host-protocol\.so\.0\]' \
    || fail "the library does not carry the soname libmod-host-protocol.so.0"
[ -f "$prefix/share/mod-host/host-scenarios.txt" ] || fail "no scenario corpus"

export PKG_CONFIG_PATH="$lib/pkgconfig"
cflags=$(pkg-config --cflags mod-host-protocol) || fail "pkg-config does not find mod-host-protocol"
libs=$(pkg-config --libs mod-host-protocol)
[ "$(pkg-config --variable=scenarios mod-host-protocol)" = "$prefix/share/mod-host/host-scenarios.txt" ] \
    || fail "the scenarios variable does not name the installed corpus"

# every installed header stands alone, and every header the build lists is installed
for h in src/host-backend.h src/host-dispatch.h src/host-errors.h src/mod-host.h src/host-scenario.h \
         src/protocol.h src/socket.h src/utils.h; do
    [ -f "$prefix/include/mod-host/${h#src/}" ] || fail "${h#src/} is not installed"
done
for h in "$prefix"/include/mod-host/*.h; do
    printf '#include <%s>\nint main(void) { return 0; }\n' "$(basename "$h")" > "$work/one.c"
    # shellcheck disable=SC2086
    $CC -std=gnu99 -Wall -Wextra -Werror $cflags -fsyntax-only "$work/one.c" || fail "$(basename "$h") does not compile alone"
done

# a consumer built from pkg-config alone links the library and runs from it
cat > "$work/consumer.c" <<'C'
#include <socket.h>
#include <protocol.h>
#include <host-dispatch.h>
#include <stdio.h>
#include <string.h>
static void quit(proto_t *proto) { protocol_response_int(0, proto); }
int main(void)
{
    const char *msg;
    protocol_add_command("quit", quit);
    msg = protocol_error_message(-1);
    if (msg == NULL || msg[0] == '\0')
        return 1;
    socket_set_idle_interval(10);
    protocol_remove_commands();
    printf("ok: %s\n", msg);
    return 0;
}
C
# shellcheck disable=SC2086
$CC -std=gnu99 -Wall -Wextra -Werror $cflags -o "$work/consumer" "$work/consumer.c" $libs \
    || fail "a consumer does not build from pkg-config alone"
readelf -d "$work/consumer" | grep -q 'NEEDED.*\[libmod-host-protocol\.so\.0\]' || fail "the consumer does not need the soname"
LD_LIBRARY_PATH="$lib" "$work/consumer" || fail "the consumer does not run"

# a staged install, as the packages do it: DESTDIR stays out of the .pc file
stage=$work/stage
make -s install-lib PREFIX=/usr LIBDIR=/usr/lib64 DESTDIR="$stage" >/dev/null
pc=$stage/usr/lib64/pkgconfig/mod-host-protocol.pc
[ -f "$pc" ] || fail "no .pc under DESTDIR/LIBDIR/pkgconfig"
grep -q "$stage" "$pc" && fail "the .pc file names DESTDIR"
grep -qx 'prefix=/usr' "$pc" || fail "the staged .pc does not say prefix=/usr"
grep -qx 'libdir=${prefix}/lib64' "$pc" || fail "the staged .pc does not follow LIBDIR"

# make install keeps its meaning: the host, its JACK internal clients and the manual page, no library
make -n install PREFIX=/usr | grep -q 'libmod-host-protocol\|include/mod-host\|mod-host-protocol\.pc' \
    && fail "make install installs the protocol library"

echo "install-lib: library, links, headers, corpus and mod-host-protocol.pc check out"
