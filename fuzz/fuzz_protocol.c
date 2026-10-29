/* The command parser alone: protocol_parse() over a table of commands that has every shape the real one
   has (fixed words, %i/%s/%f wildcards, a trailing "..."), with callbacks that only count what they were
   given. Properties: no crash, no leak, and a callback only ever runs with the argument count its pattern
   allows (exactly, or at least without the "..." for a variable pattern). */
#include "fuzz.h"

static int g_called;

static const struct { const char *pattern; uint32_t min, max; } g_table[] = {
    { "add %s %i",              3, 3 },
    { "remove %i",              2, 2 },
    { "param_set %i %s %f",     4, 4 },
    { "param_get %i %s",        3, 3 },
    { "connect %s %s",          3, 3 },
    { "quit",                   1, 1 },
    { "cpu_load",               1, 1 },
    { "midi_map %i %s %i %i",   5, 5 },
    { "patch_set %i %s ...",    3, UINT32_MAX },
    { "state_save ...",         1, UINT32_MAX },
};

/* one callback per row, so each checks the count its own pattern allows */
static void check(proto_t *proto, unsigned row)
{
    g_called++;
    /* a "..." pattern is called with its words before the "..." at least */
    uint32_t min = g_table[row].max == UINT32_MAX ? g_table[row].min - 1 : g_table[row].min;
    if (proto->list_count < min || proto->list_count > g_table[row].max)
        abort();
    for (uint32_t i = 0; i < proto->list_count; i++)
        if (proto->list[i] == NULL)
            abort();
    protocol_response_int((int)proto->list_count, proto);
}

#define CB(n) static void cb##n(proto_t *proto) { check(proto, n); }
CB(0) CB(1) CB(2) CB(3) CB(4) CB(5) CB(6) CB(7) CB(8) CB(9)
static void (*const g_cbs[])(proto_t *) = { cb0, cb1, cb2, cb3, cb4, cb5, cb6, cb7, cb8, cb9 };

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    fuzz_peer_open();
    for (unsigned i = 0; i < sizeof(g_table) / sizeof(g_table[0]); i++)
        protocol_add_command(g_table[i].pattern, g_cbs[i]);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > FUZZ_MAX_INPUT)
        return 0;

    g_called = 0;

    msg_t msg;
    msg.data = fuzz_message(data, size);
    msg.data_size = strlen(msg.data);
    msg.sender_id = fuzz_sender_fd;
    protocol_parse(&msg);
    free(msg.data);
    fuzz_peer_drain();

    for (int code = -1; code >= -4; code--)
        if (protocol_error_message(code) == NULL)
            abort();
    return 0;
}
