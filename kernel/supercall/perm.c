#include <linux/types.h>
#include <linux/limits.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/string.h>

#include "supercall/internal.h"
#include "manager/manager_identity.h"
#include "policy/allowlist.h"

#include "compat/kernel_compat.h"

bool only_manager(void)
{
    return is_manager();
}

bool only_root(void)
{
    return ksu_get_uid_t(current_uid()) == 0;
}

bool manager_or_root(void)
{
    return ksu_get_uid_t(current_uid()) == 0 || is_manager();
}

/* WebKSU: 授权名单读写仅限 管理器 或 部署在固定路径的 webksu_suctl（root）。
 * 阻止任意 root 进程直接调用 supercall 改写授权名单。 */
static bool current_exe_equals(const char *expect)
{
    struct mm_struct *mm;
    struct file *exe_file;
    char *buf, *path;
    bool ok = false;

    mm = get_task_mm(current);
    if (!mm)
        return false;

    exe_file = get_mm_exe_file(mm);
    mmput(mm);
    if (!exe_file)
        return false;

    buf = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!buf) {
        fput(exe_file);
        return false;
    }

    path = d_path(&exe_file->f_path, buf, PATH_MAX);
    if (!IS_ERR(path))
        ok = strcmp(path, expect) == 0;

    kfree(buf);
    fput(exe_file);
    return ok;
}

bool manager_or_suctl(void)
{
    if (is_manager())
        return true;
    if (ksu_get_uid_t(current_uid()) != 0)
        return false;
    return current_exe_equals("/data/adb/webksu/webksu_suctl");
}

bool always_allow(void)
{
    return true;
}

bool allowed_for_su(void)
{
    bool is_allowed = is_manager() || ksu_is_allow_uid_for_current(ksu_get_uid_t(current_uid()));

    return is_allowed;
}
