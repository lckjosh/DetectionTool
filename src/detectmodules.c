#include "main.h"

#define BETWEEN_PTR(x, y, z) (        \
    ((uintptr_t)x >= (uintptr_t)y) && \
    ((uintptr_t)x < ((uintptr_t)y + (uintptr_t)z)))

// scan for hidden modules
int scan_modules(void)
{
    struct kset *mod_kset;
    struct kobject *cur, *tmp;
    struct module_kobject *kobj;
    int found = 0;

    printk(KERN_INFO "detection tool: Scanning Modules...\n");

    mod_kset = (void *)kallsyms_lookup_name("module_kset");
    if (mod_kset)
    {
        list_for_each_entry_safe(cur, tmp, &mod_kset->list, entry)
        {
            if (!kobject_name(tmp))
                break;

            kobj = container_of(tmp, struct module_kobject, kobj);

            if (kobj && kobj->mod && kobj->mod->name)
            {
                mutex_lock(&module_mutex);
                if (!find_module(kobj->mod->name))
                {
                    printk(KERN_ALERT "detection tool: Module [%s] hidden.\n", kobj->mod->name);
                    found++;
                }
                mutex_unlock(&module_mutex);
            }
        }
    }
    return found;
}

const char *find_hidden_module_name(unsigned long addr)
{
    const char *mod_name = NULL;
    struct kset *mod_kset;
    struct kobject *cur, *tmp;
    struct module_kobject *kobj;

    mod_kset = (void *)kallsyms_lookup_name("module_kset");
    if (!mod_kset)
        return NULL;

    list_for_each_entry_safe(cur, tmp, &mod_kset->list, entry)
    {
        if (!kobject_name(tmp))
            break;

        kobj = container_of(tmp, struct module_kobject, kobj);
        if (!kobj || !kobj->mod)
            continue;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
        if (BETWEEN_PTR(addr, kobj->mod->core_layout.base, kobj->mod->core_layout.size))
        {
            mod_name = kobj->mod->name;
        }
#else
        if (BETWEEN_PTR(addr, kobj->mod->module_core, kobj->mod->core_size))
        {
            mod_name = kobj->mod->name;
        }
#endif
    }
    return mod_name;
}

struct module *get_module_from_addr(unsigned long addr)
{
    return __module_address(addr);
}