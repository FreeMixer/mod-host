/* The scenario file reader: host_scenario_load() over any bytes, with $NAME substitution, then
   host_scenario_free(). Properties: no crash, no leak, and a load that answers a count leaves exactly that
   many lines, each with a command and a reply. */
#include "fuzz.h"
#include "../src/host-scenario.h"
#include <stdio.h>

static char g_path[64];

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    snprintf(g_path, sizeof(g_path), "/tmp/fuzz-scenario-%d.txt", (int)getpid());
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const host_scenario_var_t vars[] = {
        { "URI", "http://example.org/plugin" }, { "PORT_A", "system:capture_1" }, { "EMPTY", "" },
    };
    host_scenario_list_t list;
    FILE *fp;

    if (size > FUZZ_MAX_INPUT)
        return 0;
    fp = fopen(g_path, "w");
    /* not a property: the harness could not write its scratch file */
    if (!fp)
        abort();
    fwrite(data, 1, size, fp);
    fclose(fp);

    int n = host_scenario_load(g_path, vars, 3, &list);
    if (n >= 0)
    {
        /* A load answers the number of lines it kept, and never keeps more than the list holds.
           mutant: src/host-scenario.c:242 `return list->count;` -> `return list->count + 1;`
           input: host-scenarios */
        if (n != list.count || n > HOST_SCENARIO_MAX_LINES)
            abort();
        /* Each line kept has its command and its reply.
           mutant: src/host-scenario.c:238 `sc->reply = substitute(trim(arrow + 2), vars, var_count);` -> `sc->reply = NULL;`
           input: host-scenarios */
        for (int i = 0; i < n; i++)
            if (list.lines[i].command == NULL || list.lines[i].reply == NULL)
                abort();
        host_scenario_free(&list);
    }
    return 0;
}
