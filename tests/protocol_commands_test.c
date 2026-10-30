/*
 * The protocol's command table holds PROTOCOL_MAX_COMMANDS commands, and one more is refused out loud: a host that
 * registers more than the table holds learns it from the return code and stderr, instead of losing the last
 * commands it registered (omx-clap-host lost quit to the 64 the table held before).
 */

#include <stdio.h>
#include <string.h>

#include "../src/protocol.h"

static void callback(proto_t *proto)
{
    (void)proto;
}

int main(void)
{
    static char names[PROTOCOL_MAX_COMMANDS + 1][32];
    int i, failures = 0;

    if (PROTOCOL_MAX_COMMANDS < 128)
    {
        printf("FAIL the table holds %d commands, fewer than 128\n", PROTOCOL_MAX_COMMANDS);
        failures++;
    }
    for (i = 0; i < PROTOCOL_MAX_COMMANDS; i++)
    {
        snprintf(names[i], sizeof(names[i]), "verb_%d %%i", i);
        if (protocol_add_command(names[i], callback) != 0)
        {
            printf("FAIL command %d of %d was refused\n", i + 1, PROTOCOL_MAX_COMMANDS);
            failures++;
            break;
        }
    }
    snprintf(names[PROTOCOL_MAX_COMMANDS], sizeof(names[0]), "one_too_many %%i");
    if (protocol_add_command(names[PROTOCOL_MAX_COMMANDS], callback) != -1)
    {
        printf("FAIL the command past the table was not refused\n");
        failures++;
    }
    if (failures == 0)
        printf("protocol commands ok: %d registered, the next one refused\n", PROTOCOL_MAX_COMMANDS);
    return failures ? 1 : 0;
}
