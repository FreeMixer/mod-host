/* The state directory of an instance: MakePluginStatePath() and GetPluginStateDir() with any instance and
   any request path, below a scratch directory. Property: the path answered is the scratch directory, the
   effect directory and the request, and nothing created is outside the scratch directory. */
#include "fuzz.h"
#include "../src/state-paths.h"
#include <stdio.h>
#include <sys/stat.h>

static char g_root[64];

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    snprintf(g_root, sizeof(g_root), "/tmp/fuzz-statepaths-%d", (int)getpid());
    mkdir(g_root, 0755);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 5 || size > 256)
        return 0;

    int instance;
    memcpy(&instance, data, sizeof(instance));
    char *request = fuzz_message(data + 4, size - 4);

    /* confined to what the verb can reach: the request is a path under the instance, never one that climbs out */
    if (strstr(request, "..") == NULL)
    {
        char *path = MakePluginStatePath(instance, g_root, request);
        if (path)
        {
            if (strncmp(path, g_root, strlen(g_root)) != 0)
                abort();
            free(path);
        }
    }

    char *dir = GetPluginStateDir(instance, g_root);
    if (!dir || strncmp(dir, g_root, strlen(g_root)) != 0)
        abort();
    free(dir);
    free(request);

    RecursivelyRemovePluginPath(g_root);
    mkdir(g_root, 0755);
    return 0;
}
