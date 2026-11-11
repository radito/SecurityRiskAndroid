// CI fixture: a no-op Zygisk module that stays loaded in every app process.
//
// Root hiders such as Shamiko only disguise *other* modules' libraries that remain
// mapped in the app (Shamiko unloads itself). Without a resident module there is
// nothing to hide, so the matrix installs this fixture to give the hider a target:
//   - zygisk leg:  fixture .so visible by its /data/adb/modules/... path
//   - shamiko leg: fixture code expected as an executable "[anon:.bss]" region
//
// Zygisk API v4 ABI (same layout as Magisk's zygisk.hpp). The module never calls
// setOption(DLCLOSE_MODULE_LIBRARY), so the library stays mapped after specialize.
#include <stdbool.h>
#include <stddef.h>

struct module_abi {
    long api_version;
    void *impl;
    void (*preAppSpecialize)(void *, void *);
    void (*postAppSpecialize)(void *, const void *);
    void (*preServerSpecialize)(void *, void *);
    void (*postServerSpecialize)(void *, const void *);
};

struct api_table {
    void *impl;
    bool (*registerModule)(struct api_table *, struct module_abi *);
    /* remaining entries are unused by this fixture */
};

static volatile int g_specialize_count;

static void pre_app(void *self, void *args) { (void)self; (void)args; g_specialize_count++; }
static void post_app(void *self, const void *args) { (void)self; (void)args; g_specialize_count++; }
static void pre_server(void *self, void *args) { (void)self; (void)args; }
static void post_server(void *self, const void *args) { (void)self; (void)args; }

static struct module_abi g_abi = {
    .api_version = 4,
    .impl = NULL,
    .preAppSpecialize = pre_app,
    .postAppSpecialize = post_app,
    .preServerSpecialize = pre_server,
    .postServerSpecialize = post_server,
};

__attribute__((visibility("default")))
void zygisk_module_entry(struct api_table *table, void *env) {
    (void)env;
    if (table && table->registerModule) {
        g_abi.impl = &g_abi;
        table->registerModule(table, &g_abi);
    }
}
