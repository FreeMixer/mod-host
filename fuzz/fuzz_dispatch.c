/* The whole command dispatcher: host_dispatch_register() and its monitor_output, plugin-info and
   unsupported tables over a backend whose answers depend on the input, then protocol_parse(). The backend
   answers every error code the host defines, so each verb's mapping of a return value to a reply is reached.
   Properties: no crash, no leak, and every reply is one NUL-terminated string: "resp <int>", alone or followed
   by the values of the verb, or an error message of protocol_error_message(). */
#include "fuzz.h"
#include "../src/host-backend.h"
#include "../src/host-dispatch.h"
#include "../src/host-errors.h"

static unsigned g_salt;

static int answer(int instance)
{
    static const int codes[] = {
        SUCCESS, ERR_INSTANCE_INVALID, ERR_INSTANCE_ALREADY_EXISTS, ERR_INSTANCE_NON_EXISTS,
        ERR_INSTANCE_UNLICENSED, ERR_LV2_INVALID_URI, ERR_INVALID_OPERATION, ERR_JACK_PORT_CONNECTION,
        ERR_LV2_CANT_LOAD_STATE,
    };
    return codes[((unsigned)instance + g_salt) % (sizeof(codes) / sizeof(codes[0]))];
}

static int f_add(const char *uri, int instance, const char *client) { (void)uri; (void)client; return instance >= 0 ? instance : answer(instance); }
static int f_remove(int instance) { return answer(instance); }
static int f_bypass(int instance, int value) { (void)value; return answer(instance); }
static int f_param_set(int instance, const char *symbol, float value) { (void)symbol; (void)value; return answer(instance); }
static int f_param_get(int instance, const char *symbol, float *value) { (void)symbol; *value = (float)instance; return answer(instance); }
static int f_preset_load(int instance, const char *uri) { (void)uri; return answer(instance); }
static int f_state_save(const char *dir) { return answer((int)strlen(dir)); }
static int f_state_load(const char *dir) { return answer((int)strlen(dir)); }
static int f_connect(const char *a, const char *b) { return answer((int)(strlen(a) + strlen(b))); }
static int f_disconnect(const char *a, const char *b) { return answer((int)(strlen(a) + strlen(b))); }
static int f_monitor_output(int instance, const char *symbol) { (void)symbol; return answer(instance); }
static int f_track_info(int instance, const char *name, const char *color, const char *kind)
{ (void)name; (void)color; (void)kind; return answer(instance); }
static int f_remote_pages(int instance) { return instance < 0 ? answer(instance) : instance % 4; }
static int f_remote_page_get(int instance, int page, host_remote_page_t *out)
{
    if (instance < 0 || page < 0)
        return answer(instance);
    memset(out, 0, sizeof(*out));
    out->id = (uint32_t)page;
    strcpy(out->section, "Main \"A\"\\");
    strcpy(out->name, "Page");
    strcpy(out->slots[0], "gain");
    return SUCCESS;
}
static int f_param_info(int instance, const char *symbol, host_param_info_t *info)
{
    (void)symbol;
    if (instance < 0)
        return answer(instance);
    info->unit = "hz"; info->scale = "log";
    info->min = 20; info->max = 20000; info->def = 440; info->step = (double)(instance % 3);
    info->stable_symbol = "stable";
    return SUCCESS;
}

static const host_backend_t g_backend = {
    f_add, f_remove, f_bypass, f_param_set, f_param_get, f_preset_load,
    f_state_save, f_state_load, f_connect, f_disconnect,
};
static const host_plugin_info_t g_info = { f_track_info, f_remote_pages, f_remote_page_get, f_param_info };

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    fuzz_peer_open();
    host_dispatch_register(&g_backend);
    host_dispatch_register_monitor_output(f_monitor_output);
    host_dispatch_register_plugin_info(&g_info);
    host_dispatch_register_unsupported();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1 || size > FUZZ_MAX_INPUT)
        return 0;

    g_salt = data[0];
    msg_t msg;
    msg.data = fuzz_message(data + 1, size - 1);
    msg.data_size = strlen(msg.data);
    msg.sender_id = fuzz_sender_fd;
    protocol_parse(&msg);
    free(msg.data);

    char reply[8192];
    ssize_t n = read(fuzz_peer_fd, reply, sizeof(reply) - 1);
    if (n > 0)
    {
        /* One answer per command, sent with its NUL: the NUL is the last byte read and the only one.
           mutant: src/protocol.c:224 `proto.response_size+1` -> `proto.response_size`
           input: scenario-1 */
        if (memchr(reply, '\0', (size_t)n) != reply + n - 1)
            abort();
        /* The answer is a protocol error message, or "resp" and an integer, then the end or a space.
           mutant: src/protocol.c:276 `"resp %i"` -> `"rsp %i"`
           input: scenario-1 */
        int known = 0;
        for (int code = -1; code >= -4 && !known; code--)
            known = strcmp(reply, protocol_error_message(code)) == 0;
        if (!known)
        {
            const char *p = reply + 5;
            if (strncmp(reply, "resp ", 5) != 0)
                abort();
            if (*p == '-')
                p++;
            if (*p < '0' || *p > '9')
                abort();
            while (*p >= '0' && *p <= '9')
                p++;
            if (*p != '\0' && *p != ' ')
                abort();
        }
    }
    fuzz_peer_drain();
    return 0;
}
