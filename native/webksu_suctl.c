/*
 * webksu_suctl — WebKSU 内核 supercall 工具（读取/管理 Root 授权名单）
 *
 * 通过 ReSukiSU 内核的 reboot 钩子安装 [ksu_driver] fd，再对其 ioctl：
 *   info                          内核信息（验证通路）
 *   list                          输出 {"allow":[uid...],"deny":[uid...]}
 *   granted <uid>                 查询 uid 是否已授权 -> {"uid":n,"granted":bool}
 *   grant <pkg> <uid>             授予 root（SET_APP_PROFILE allow_su=1）
 *   revoke <pkg> <uid>            撤销 root（SET_APP_PROFILE allow_su=0）
 *   get <uid>                     dump 该 uid 的 app profile
 *
 * 权限：list/granted 现有 ReSukiSU 内核即允许 root；
 *       grant/revoke/get 需内核 patch（SET/GET_APP_PROFILE 放行 root）。
 *
 * 构建（zig 静态交叉编译）：
 *   zig cc -target aarch64-linux-musl -O2 -static -o webksu_suctl.aarch64 webksu_suctl.c
 *   zig cc -target arm-linux-musleabihf  -O2 -static -o webksu_suctl.armv7   webksu_suctl.c
 *   zig cc -target x86_64-linux-musl     -O2 -static -o webksu_suctl.x86_64  webksu_suctl.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>

/* ---------- 类型（与内核 uapi 一致） ---------- */
typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef int            s32;
typedef long long      s64;
typedef unsigned long long u64;

#define KSU_INSTALL_MAGIC1 0xDEADBEEFu
#define KSU_INSTALL_MAGIC2 0xCAFEBABEu

#define KSU_APP_PROFILE_VER 4
#define KSU_MAX_PACKAGE_NAME 256
#define KSU_MAX_GROUPS 32
#define KSU_SELINUX_DOMAIN 64

struct root_profile {
    s32 uid; s32 gid;
    u32 groups_count; s32 groups[KSU_MAX_GROUPS];
    struct { u64 effective, permitted, inheritable; } capabilities;
    char selinux_domain[KSU_SELINUX_DOMAIN];
    s32 namespaces;
    u64 flags;
};

struct non_root_profile { u8 umount_modules; };

struct app_profile {
    u32 version;
    char key[KSU_MAX_PACKAGE_NAME];
    s32 curr_uid;
    u8 allow_su; /* bool */
    union {
        struct { u8 use_default; char template_name[KSU_MAX_PACKAGE_NAME]; struct root_profile profile; } rp_config;
        struct { u8 use_default; struct non_root_profile profile; } nrp_config;
    };
};

struct ksu_get_info_cmd { u32 version, flags, features, uapi_version; };
struct ksu_new_get_allow_list_cmd { u16 count, total_count; u32 uids[]; };
struct ksu_uid_granted_root_cmd { u32 uid; u8 granted; };
struct ksu_get_app_profile_cmd { struct app_profile profile; };
struct ksu_set_app_profile_cmd { struct app_profile profile; };

/* ---------- ioctl 号（asm-generic 定义，aarch64/arm/x86_64 一致） ---------- */
#define KSU_IOC(d, t, nr, sz) ((u32)((d) << 30 | (sz) << 16 | (t) << 8 | (nr)))
#define KSU_IOC_NOSZ(d, t, nr) KSU_IOC(d, t, nr, 0)
#define KSU_IOCTL_GET_INFO            KSU_IOC(2U, 'K', 2,  sizeof(struct ksu_get_info_cmd))
#define KSU_IOCTL_NEW_GET_ALLOW_LIST  KSU_IOC(3U, 'K', 6,  4) /* header: u16 count + u16 total */
#define KSU_IOCTL_NEW_GET_DENY_LIST   KSU_IOC(3U, 'K', 7,  4)
#define KSU_IOCTL_UID_GRANTED_ROOT    KSU_IOC(3U, 'K', 8,  0)
#define KSU_IOCTL_GET_APP_PROFILE     KSU_IOC(3U, 'K', 11, 0)
#define KSU_IOCTL_SET_APP_PROFILE     KSU_IOC(1U, 'K', 12, 0)

/* ---------- 安装 supercall driver fd ---------- */
static int ksu_install_fd(void) {
    int fd = -1;
    /*
     * 注意：ReSukiSU 的 reboot 钩子(pre-handler)安装 fd 后会放行原始
     * reboot 系统调用继续执行，而原生 sys_reboot 因 magic 不合法必然
     * 返回 -EINVAL —— 这是预期现象，不能以 syscall 返回值判断成败。
     * 唯一可靠的判据是出参 fd 是否被内核 copy_to_user 写入有效值。
     */
    errno = 0;
    syscall(SYS_reboot, (int)KSU_INSTALL_MAGIC1, (int)KSU_INSTALL_MAGIC2, 0, &fd);
    if (fd < 0) {
        if (!errno) errno = EINVAL;
        return -1;
    }
    return fd;
}

static int fail(int code, const char *msg) {
    fprintf(stderr, "webksu_suctl: %s (errno=%d %s)\n", msg, errno, strerror(errno));
    return code;
}

static void print_uid_array(const char *name, int fd, u32 ioctl_cmd) {
    /* 第一次 count=0 拿 total_count，再取全量 */
    struct { u16 count, total_count; } hdr;
    memset(&hdr, 0, sizeof(hdr));
    if (ioctl(fd, ioctl_cmd, &hdr) != 0) { fprintf(stderr, "\"%s\":[],\"%s_err\":\"%s\"", name, name, strerror(errno)); return; }
    int total = hdr.total_count;
    printf("\"%s\":[", name);
    if (total > 0) {
        size_t buf_sz = 4 + (size_t)total * sizeof(u32);
        u32 *buf = malloc(buf_sz);
        if (!buf) { printf("],\"%s_err\":\"oom\"", name); return; }
        ((u16 *)buf)[0] = (u16)total; /* count = total */
        ((u16 *)buf)[1] = 0;
        if (ioctl(fd, ioctl_cmd, buf) != 0) {
            printf("],\"%s_err\":\"%s\"", name, strerror(errno));
            free(buf);
            return;
        }
        u16 got = ((u16 *)buf)[0];
        const u32 *uids = (const u32 *)((char *)buf + 4);
        for (int i = 0; i < got; i++) printf("%s%u", i ? "," : "", uids[i]);
        free(buf);
    }
    printf("]");
}

static void make_profile(struct app_profile *p, const char *pkg, long uid, int allow) {
    memset(p, 0, sizeof(*p));
    p->version = KSU_APP_PROFILE_VER;
    strncpy(p->key, pkg, KSU_MAX_PACKAGE_NAME - 1);
    p->curr_uid = (s32)uid;
    p->allow_su = allow ? 1 : 0;
    if (allow) {
        /* 内核 profile_valid() 要求：selinux_domain 非空、groups_count <= 32 */
        struct root_profile *rp = &p->rp_config.profile;
        p->rp_config.use_default = 1; /* 跟随全局默认 root 配置 */
        rp->uid = 0;
        rp->gid = 0;
        rp->groups_count = 1;
        rp->groups[0] = 0;
        rp->capabilities.effective = ~0ULL;
        rp->capabilities.permitted = ~0ULL;
        rp->capabilities.inheritable = ~0ULL;
        strncpy(rp->selinux_domain, "u:r:su:s0", KSU_SELINUX_DOMAIN - 1);
        rp->namespaces = 0;
        rp->flags = 1ULL << 0; /* FLAG_KSU_NO_NEW_PRIVS，与新版管理器默认一致 */
    } else {
        p->nrp_config.use_default = 1;
        p->nrp_config.profile.umount_modules = 0;
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr,
            "用法: webksu_suctl <命令> [参数]\n"
            "  info | list | granted <uid> | grant <pkg> <uid> | revoke <pkg> <uid> | get <uid>\n");
        return 1;
    }
    const char *cmd = argv[1];

    if (geteuid() != 0) return fail(2, "需要 root 权限运行");

    /* 写操作（grant/revoke）必须携带令牌：与 /data/adb/webksu/token 比对。
     * 令牌仅由 WebKSU 网页服务器持有并通过 HTTP 头下发，普通 root 进程
     * 即使能运行 suctl，没有令牌也无法改写授权名单。 */
    int is_write = (!strcmp(cmd, "grant") || !strcmp(cmd, "revoke"));
    const char *tok = getenv("WKSU_TOKEN");
    if (is_write) {
        if (!tok || !*tok) return fail(5, "缺少 WKSU_TOKEN（授权写操作仅限 Web 管理器）");
        char expect[129];
        int f = open("/data/adb/webksu/token", O_RDONLY);
        if (f < 0) return fail(5, "无法读取令牌文件（服务器未初始化?）");
        ssize_t n = read(f, expect, sizeof(expect) - 1);
        close(f);
        if (n <= 32) return fail(5, "令牌文件无效");
        expect[n] = 0;
        /* 去尾部换行 */
        while (n > 0 && (expect[n-1] == '\n' || expect[n-1] == '\r')) expect[--n] = 0;
        if (!tok || strcmp(tok, expect) != 0) return fail(5, "令牌校验失败");
    }

    int fd = ksu_install_fd();
    if (fd < 0) return fail(2, "无法安装内核 supercall fd（未检测到 ReSukiSU/KSU 内核?）");

    int rc = 0;
    if (!strcmp(cmd, "info")) {
        struct ksu_get_info_cmd info;
        memset(&info, 0, sizeof(info));
        if (ioctl(fd, KSU_IOCTL_GET_INFO, &info) != 0) { close(fd); return fail(3, "GET_INFO 失败"); }
        printf("{\"version\":%u,\"flags\":%u,\"features\":%u,\"uapi_version\":%u}\n",
               info.version, info.flags, info.features, info.uapi_version);
    } else if (!strcmp(cmd, "list")) {
        printf("{");
        print_uid_array("allow", fd, KSU_IOCTL_NEW_GET_ALLOW_LIST);
        printf(",");
        print_uid_array("deny", fd, KSU_IOCTL_NEW_GET_DENY_LIST);
        printf("}\n");
    } else if (!strcmp(cmd, "granted")) {
        if (argc < 3) { close(fd); fprintf(stderr, "缺 uid\n"); return 1; }
        struct ksu_uid_granted_root_cmd c;
        c.uid = (u32)strtoul(argv[2], NULL, 10);
        c.granted = 0;
        if (ioctl(fd, KSU_IOCTL_UID_GRANTED_ROOT, &c) != 0) { close(fd); return fail(3, "UID_GRANTED_ROOT 失败"); }
        printf("{\"uid\":%u,\"granted\":%s}\n", c.uid, c.granted ? "true" : "false");
    } else if (!strcmp(cmd, "grant") || !strcmp(cmd, "revoke")) {
        if (argc < 4) { close(fd); fprintf(stderr, "用法: %s <pkg> <uid>\n", cmd); return 1; }
        struct ksu_set_app_profile_cmd c;
        make_profile(&c.profile, argv[2], strtol(argv[3], NULL, 10), !strcmp(cmd, "grant"));
        if (ioctl(fd, KSU_IOCTL_SET_APP_PROFILE, &c) != 0) {
            close(fd);
            if (errno == EPERM || errno == EACCES)
                return fail(4, "内核拒绝 root 写入授权（SET_APP_PROFILE 仅限管理器，请刷入 WebKSU 内核 patch）");
            return fail(3, "SET_APP_PROFILE 失败");
        }
        printf("{\"ok\":true,\"op\":\"%s\",\"key\":\"%s\",\"uid\":%d}\n", cmd, argv[2], c.profile.curr_uid);
    } else if (!strcmp(cmd, "get")) {
        if (argc < 3) { close(fd); fprintf(stderr, "缺 uid\n"); return 1; }
        struct ksu_get_app_profile_cmd c;
        memset(&c, 0, sizeof(c));
        c.profile.curr_uid = (s32)strtol(argv[2], NULL, 10);
        if (ioctl(fd, KSU_IOCTL_GET_APP_PROFILE, &c) != 0) {
            close(fd);
            if (errno == ENOENT) { printf("{\"found\":false,\"uid\":%d}\n", c.profile.curr_uid); return 0; }
            if (errno == EPERM || errno == EACCES)
                return fail(4, "内核拒绝 root 读取 profile（GET_APP_PROFILE 仅限管理器，请刷入 WebKSU 内核 patch）");
            return fail(3, "GET_APP_PROFILE 失败");
        }
        printf("{\"found\":true,\"uid\":%d,\"key\":\"%s\",\"allow_su\":%s}\n",
               c.profile.curr_uid, c.profile.key, c.profile.allow_su ? "true" : "false");
    } else {
        close(fd);
        fprintf(stderr, "未知命令: %s\n", cmd);
        return 1;
    }
    close(fd);
    return rc;
}
