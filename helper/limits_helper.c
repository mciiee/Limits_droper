#define _GNU_SOURCE

#include <cpuid.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <math.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define MCHBAR_BASE 0xFEDC0000ULL
#define MAP_SIZE    (2 * 1024 * 1024)
#define PL_OFF      0x59A0

#define MSR_OC_MAILBOX       0x150
#define MSR_IA32_PERF_CTL     0x199
#define MSR_IA32_PERF_STATUS  0x198
#define MSR_RAPL_POWER_UNIT  0x606
#define MSR_PKG_POWER_LIMIT  0x610

#define CORE_TYPE_ATOM 0x20
#define CORE_TYPE_CORE 0x40

#define OC_PLANE_CORE 0x0

static int rdmsr(int fd, uint32_t reg, uint64_t *out) {
    ssize_t n = pread(fd, out, sizeof(*out), reg);
    if (n != (ssize_t)sizeof(*out)) {
        return -1;
    }
    return 0;
}

static int wrmsr(int fd, uint32_t reg, uint64_t val) {
    ssize_t n = pwrite(fd, &val, sizeof(val), reg);
    if (n != (ssize_t)sizeof(val)) {
        return -1;
    }
    return 0;
}

static int open_msr_cpu(int cpu, bool write) {
    char path[64];
    snprintf(path, sizeof(path), "/dev/cpu/%d/msr", cpu);
    return open(path, write ? O_RDWR : O_RDONLY);
}

static int open_msr(bool write) {
    return open_msr_cpu(0, write);
}

static int open_mmio(bool write, volatile uint8_t **out_base) {
    int fd = open("/dev/mem", (write ? O_RDWR : O_RDONLY) | O_SYNC);
    if (fd < 0) {
        return -1;
    }

    int prot = write ? (PROT_READ | PROT_WRITE) : PROT_READ;
    void *map = mmap(NULL, MAP_SIZE, prot, MAP_SHARED, fd, MCHBAR_BASE);
    if (map == MAP_FAILED) {
        close(fd);
        return -1;
    }

    *out_base = (volatile uint8_t *)map;
    return fd;
}

static void close_mmio(int fd, volatile uint8_t *base) {
    if (base && base != MAP_FAILED) {
        munmap((void *)base, MAP_SIZE);
    }
    if (fd >= 0) {
        close(fd);
    }
}

static uint64_t rd64(volatile uint8_t *base, uint32_t off) {
    volatile uint32_t *p32 = (volatile uint32_t *)(base + off);
    uint64_t lo = p32[0];
    uint64_t hi = p32[1];
    return lo | (hi << 32);
}

static void wr64(volatile uint8_t *base, uint32_t off, uint64_t v) {
    volatile uint32_t *p32 = (volatile uint32_t *)(base + off);
    p32[0] = (uint32_t)(v & 0xffffffffu);
    p32[1] = (uint32_t)(v >> 32);
    (void)p32[1];
}

struct cpu_list {
    int *ids;
    size_t count;
    size_t cap;
};

static void cpu_list_init(struct cpu_list *list) {
    list->ids = NULL;
    list->count = 0;
    list->cap = 0;
}

static void cpu_list_free(struct cpu_list *list) {
    free(list->ids);
    list->ids = NULL;
    list->count = 0;
    list->cap = 0;
}

static int cpu_list_add(struct cpu_list *list, int cpu) {
    if (list->count == list->cap) {
        size_t next = list->cap ? list->cap * 2 : 8;
        int *new_ids = realloc(list->ids, next * sizeof(*new_ids));
        if (!new_ids) {
            return -1;
        }
        list->ids = new_ids;
        list->cap = next;
    }
    list->ids[list->count++] = cpu;
    return 0;
}

static int cpu_is_online(int cpu) {
    char path[128];
    snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/online", cpu);
    FILE *f = fopen(path, "r");
    if (!f) {
        return 1;
    }
    int val = 1;
    if (fscanf(f, "%d", &val) != 1) {
        val = 1;
    }
    fclose(f);
    return val != 0;
}

static int core_type_supported(void) {
    unsigned int max = __get_cpuid_max(0, NULL);
    if (max < 0x1A) {
        return 0;
    }
    unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
    if (!__get_cpuid_count(0x1A, 0, &eax, &ebx, &ecx, &edx)) {
        return 0;
    }
    return eax != 0;
}

static int detect_core_type(int cpu, int *out_type) {
    cpu_set_t old_set;
    if (sched_getaffinity(0, sizeof(old_set), &old_set) != 0) {
        return 0;
    }

    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        return 0;
    }

    unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
    unsigned int max = __get_cpuid_max(0, NULL);
    int type = -1;

    if (max >= 0x1A && __get_cpuid_count(0x1A, 0, &eax, &ebx, &ecx, &edx) && eax != 0) {
        type = (int)((eax >> 24) & 0xFFu);
    }

    (void)sched_setaffinity(0, sizeof(old_set), &old_set);

    if (type < 0) {
        return 0;
    }
    *out_type = type;
    return 1;
}

static int enumerate_cpus(struct cpu_list *p_list, struct cpu_list *e_list, struct cpu_list *u_list, int *supports) {
    DIR *dir = opendir("/sys/devices/system/cpu");
    if (!dir) {
        return -1;
    }

    int has_core_type = core_type_supported();
    if (supports) {
        *supports = has_core_type;
    }

    struct dirent *de = NULL;
    while ((de = readdir(dir)) != NULL) {
        if (strncmp(de->d_name, "cpu", 3) != 0) {
            continue;
        }
        const char *suffix = de->d_name + 3;
        if (*suffix == '\0') {
            continue;
        }
        char *end = NULL;
        long cpu = strtol(suffix, &end, 10);
        if (!end || *end != '\0') {
            continue;
        }
        if (cpu < 0) {
            continue;
        }
        if (!cpu_is_online((int)cpu)) {
            continue;
        }

        if (!has_core_type) {
            if (cpu_list_add(p_list, (int)cpu) != 0) {
                closedir(dir);
                return -1;
            }
            continue;
        }

        int type = 0;
        int ok = detect_core_type((int)cpu, &type);
        if (!ok) {
            if (cpu_list_add(u_list, (int)cpu) != 0) {
                closedir(dir);
                return -1;
            }
            continue;
        }

        if (type == CORE_TYPE_CORE) {
            if (cpu_list_add(p_list, (int)cpu) != 0) {
                closedir(dir);
                return -1;
            }
        } else if (type == CORE_TYPE_ATOM) {
            if (cpu_list_add(e_list, (int)cpu) != 0) {
                closedir(dir);
                return -1;
            }
        } else {
            if (cpu_list_add(u_list, (int)cpu) != 0) {
                closedir(dir);
                return -1;
            }
        }
    }

    closedir(dir);
    return 0;
}

static void print_cpu_list(const char *label, const struct cpu_list *list) {
    printf("%s=", label);
    for (size_t i = 0; i < list->count; i++) {
        if (i) {
            printf(",");
        }
        printf("%d", list->ids[i]);
    }
    printf("\n");
}

static int parse_u64(const char *s, uint64_t *out) {
    if (!s || !*s) {
        return 0;
    }
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 0);
    if (s == end || *end != '\0') {
        return 0;
    }
    *out = (uint64_t)v;
    return 1;
}

static int parse_int(const char *s, int *out) {
    if (!s || !*s) {
        return 0;
    }
    char *end = NULL;
    long v = strtol(s, &end, 10);
    if (s == end || *end != '\0') {
        return 0;
    }
    *out = (int)v;
    return 1;
}

static int parse_double(const char *s, double *out) {
    if (!s || !*s) {
        return 0;
    }
    char *end = NULL;
    double v = strtod(s, &end);
    if (s == end || *end != '\0') {
        return 0;
    }
    *out = v;
    return 1;
}

static int read_ratio_on_cpu(int cpu, uint8_t *ratio_out) {
    int fd = open_msr_cpu(cpu, false);
    if (fd < 0) {
        return -1;
    }
    uint64_t val = 0;
    if (rdmsr(fd, MSR_IA32_PERF_CTL, &val) != 0) {
        close(fd);
        return -1;
    }
    close(fd);
    *ratio_out = (uint8_t)((val >> 8) & 0xFFu);
    return 0;
}

static int read_ratio_current_on_cpu(int cpu, uint8_t *ratio_out) {
    int fd = open_msr_cpu(cpu, false);
    if (fd < 0) {
        return -1;
    }
    uint64_t val = 0;
    if (rdmsr(fd, MSR_IA32_PERF_STATUS, &val) != 0) {
        close(fd);
        return -1;
    }
    close(fd);
    *ratio_out = (uint8_t)((val >> 8) & 0xFFu);
    return 0;
}

static int set_ratio_on_cpu(int cpu, uint8_t ratio) {
    int fd = open_msr_cpu(cpu, true);
    if (fd < 0) {
        return -1;
    }
    uint64_t cur = 0;
    if (rdmsr(fd, MSR_IA32_PERF_CTL, &cur) != 0) {
        close(fd);
        return -1;
    }
    uint64_t next = (cur & ~0xFFFFULL) | ((uint64_t)ratio << 8);
    if (wrmsr(fd, MSR_IA32_PERF_CTL, next) != 0) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static int apply_ratio_list(const struct cpu_list *list, uint8_t ratio) {
    for (size_t i = 0; i < list->count; i++) {
        if (set_ratio_on_cpu(list->ids[i], ratio) != 0) {
            return -1;
        }
    }
    return 0;
}

static uint32_t oc_encode_offset_mv(double mv) {
    long raw = lround(mv * 1.024);
    uint32_t val = (uint32_t)(raw & 0xFFFu);
    return val << 21;
}

static double oc_decode_offset_mv(uint32_t raw) {
    int32_t val = (int32_t)((raw >> 21) & 0xFFFu);
    if (val & 0x800) {
        val |= ~0xFFF;
    }
    return (double)val / 1.024;
}

static int oc_mailbox_read(int fd, uint8_t plane, uint32_t *data_out) {
    uint32_t cmd = 0x80000010u | ((uint32_t)plane << 8);
    uint64_t req = ((uint64_t)cmd << 32);
    if (wrmsr(fd, MSR_OC_MAILBOX, req) != 0) {
        return -1;
    }
    uint64_t resp = 0;
    if (rdmsr(fd, MSR_OC_MAILBOX, &resp) != 0) {
        return -1;
    }
    *data_out = (uint32_t)(resp & 0xFFFFFFFFu);
    return 0;
}

static int oc_mailbox_write(int fd, uint8_t plane, uint32_t data) {
    uint32_t cmd = 0x80000011u | ((uint32_t)plane << 8);
    uint64_t req = ((uint64_t)cmd << 32) | data;
    return wrmsr(fd, MSR_OC_MAILBOX, req);
}

static void usage(const char *argv0) {
    fprintf(stderr,
        "Usage:\n"
        "  %s --read\n"
        "  %s --write-msr 0xHEX64\n"
        "  %s --write-mmio 0xHEX64\n"
        "  %s --set-p-ratio <int>\n"
        "  %s --set-e-ratio <int>\n"
        "  %s --set-all-ratio <int>\n"
        "  %s --set-pe-ratio <p_int> <e_int>\n"
        "  %s --set-core-uv <mV>\n",
        argv0, argv0, argv0, argv0, argv0, argv0, argv0, argv0);
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "--help") == 0) {
        usage(argv[0]);
        return 2;
    }

    if (strcmp(argv[1], "--read") == 0) {
        int msr_fd = open_msr(true);
        if (msr_fd < 0) {
            fprintf(stderr, "open(/dev/cpu/0/msr) failed: %s\n", strerror(errno));
            return 1;
        }

        volatile uint8_t *mmio = NULL;
        int mem_fd = open_mmio(false, &mmio);
        if (mem_fd < 0) {
            fprintf(stderr, "open(/dev/mem) failed: %s\n", strerror(errno));
            close(msr_fd);
            return 1;
        }

        uint64_t rapl_units = 0;
        uint64_t msr_val = 0;
        uint64_t mmio_val = 0;

        if (rdmsr(msr_fd, MSR_RAPL_POWER_UNIT, &rapl_units) != 0) {
            fprintf(stderr, "read MSR 0x%X failed: %s\n", MSR_RAPL_POWER_UNIT, strerror(errno));
            close_mmio(mem_fd, mmio);
            close(msr_fd);
            return 1;
        }

        if (rdmsr(msr_fd, MSR_PKG_POWER_LIMIT, &msr_val) != 0) {
            fprintf(stderr, "read MSR 0x%X failed: %s\n", MSR_PKG_POWER_LIMIT, strerror(errno));
            close_mmio(mem_fd, mmio);
            close(msr_fd);
            return 1;
        }

        mmio_val = rd64(mmio, PL_OFF);

        struct cpu_list p_list;
        struct cpu_list e_list;
        struct cpu_list u_list;
        cpu_list_init(&p_list);
        cpu_list_init(&e_list);
        cpu_list_init(&u_list);
        int core_type_ok = 0;
        if (enumerate_cpus(&p_list, &e_list, &u_list, &core_type_ok) != 0) {
            fprintf(stderr, "Failed to enumerate CPUs\n");
            close_mmio(mem_fd, mmio);
            close(msr_fd);
            cpu_list_free(&p_list);
            cpu_list_free(&e_list);
            cpu_list_free(&u_list);
            return 1;
        }

        uint8_t p_ratio = 0;
        uint8_t e_ratio = 0;
        int p_ratio_valid = 0;
        int e_ratio_valid = 0;
        uint8_t p_ratio_cur = 0;
        uint8_t e_ratio_cur = 0;
        int p_ratio_cur_valid = 0;
        int e_ratio_cur_valid = 0;
        if (p_list.count > 0 && read_ratio_on_cpu(p_list.ids[0], &p_ratio) == 0) {
            p_ratio_valid = 1;
        }
        if (e_list.count > 0 && read_ratio_on_cpu(e_list.ids[0], &e_ratio) == 0) {
            e_ratio_valid = 1;
        }
        if (p_list.count > 0 && read_ratio_current_on_cpu(p_list.ids[0], &p_ratio_cur) == 0) {
            p_ratio_cur_valid = 1;
        }
        if (e_list.count > 0 && read_ratio_current_on_cpu(e_list.ids[0], &e_ratio_cur) == 0) {
            e_ratio_cur_valid = 1;
        }

        uint32_t core_uv_raw = 0;
        int core_uv_valid = 0;
        double core_uv_mv = 0.0;
        if (oc_mailbox_read(msr_fd, OC_PLANE_CORE, &core_uv_raw) == 0) {
            core_uv_valid = 1;
            core_uv_mv = oc_decode_offset_mv(core_uv_raw);
        }

        int power_unit = (int)(rapl_units & 0x0F);
        double unit_watts = 1.0 / (double)(1u << power_unit);

        printf("POWER_UNIT=%d\n", power_unit);
        printf("UNIT_WATTS=%.12f\n", unit_watts);
        printf("MSR=0x%016" PRIx64 "\n", msr_val);
        printf("MMIO=0x%016" PRIx64 "\n", mmio_val);
        printf("CORE_TYPE_SUPPORTED=%d\n", core_type_ok);
        print_cpu_list("P_CPUS", &p_list);
        print_cpu_list("E_CPUS", &e_list);
        print_cpu_list("U_CPUS", &u_list);
        printf("P_RATIO_VALID=%d\n", p_ratio_valid);
        printf("E_RATIO_VALID=%d\n", e_ratio_valid);
        printf("P_RATIO_TARGET=%u\n", p_ratio);
        printf("E_RATIO_TARGET=%u\n", e_ratio);
        printf("P_RATIO_CUR_VALID=%d\n", p_ratio_cur_valid);
        printf("E_RATIO_CUR_VALID=%d\n", e_ratio_cur_valid);
        printf("P_RATIO_CUR=%u\n", p_ratio_cur);
        printf("E_RATIO_CUR=%u\n", e_ratio_cur);
        printf("CORE_UV_VALID=%d\n", core_uv_valid);
        printf("CORE_UV_MV=%.3f\n", core_uv_mv);
        printf("CORE_UV_RAW=0x%08" PRIx32 "\n", core_uv_raw);

        close_mmio(mem_fd, mmio);
        close(msr_fd);
        cpu_list_free(&p_list);
        cpu_list_free(&e_list);
        cpu_list_free(&u_list);
        return 0;
    }

    if (strcmp(argv[1], "--write-msr") == 0) {
        if (argc < 3) {
            usage(argv[0]);
            return 2;
        }
        uint64_t val = 0;
        if (!parse_u64(argv[2], &val)) {
            fprintf(stderr, "Invalid value: %s\n", argv[2]);
            return 2;
        }
        int msr_fd = open_msr(true);
        if (msr_fd < 0) {
            fprintf(stderr, "open(/dev/cpu/0/msr) failed: %s\n", strerror(errno));
            return 1;
        }
        if (wrmsr(msr_fd, MSR_PKG_POWER_LIMIT, val) != 0) {
            fprintf(stderr, "write MSR 0x%X failed: %s\n", MSR_PKG_POWER_LIMIT, strerror(errno));
            close(msr_fd);
            return 1;
        }
        close(msr_fd);
        printf("OK\n");
        return 0;
    }

    if (strcmp(argv[1], "--write-mmio") == 0) {
        if (argc < 3) {
            usage(argv[0]);
            return 2;
        }
        uint64_t val = 0;
        if (!parse_u64(argv[2], &val)) {
            fprintf(stderr, "Invalid value: %s\n", argv[2]);
            return 2;
        }
        volatile uint8_t *mmio = NULL;
        int mem_fd = open_mmio(true, &mmio);
        if (mem_fd < 0) {
            fprintf(stderr, "open(/dev/mem) failed: %s\n", strerror(errno));
            return 1;
        }
        wr64(mmio, PL_OFF, val);
        close_mmio(mem_fd, mmio);
        printf("OK\n");
        return 0;
    }

    if (strcmp(argv[1], "--set-p-ratio") == 0 ||
        strcmp(argv[1], "--set-e-ratio") == 0 ||
        strcmp(argv[1], "--set-all-ratio") == 0) {
        if (argc < 3) {
            usage(argv[0]);
            return 2;
        }
        int ratio = 0;
        if (!parse_int(argv[2], &ratio) || ratio <= 0 || ratio > 255) {
            fprintf(stderr, "Invalid ratio: %s\n", argv[2]);
            return 2;
        }

        struct cpu_list p_list;
        struct cpu_list e_list;
        struct cpu_list u_list;
        cpu_list_init(&p_list);
        cpu_list_init(&e_list);
        cpu_list_init(&u_list);
        if (enumerate_cpus(&p_list, &e_list, &u_list, NULL) != 0) {
            fprintf(stderr, "Failed to enumerate CPUs\n");
            cpu_list_free(&p_list);
            cpu_list_free(&e_list);
            cpu_list_free(&u_list);
            return 1;
        }

        int rc = 0;
        if (strcmp(argv[1], "--set-p-ratio") == 0) {
            if (p_list.count == 0) {
                fprintf(stderr, "No P cores detected\n");
                rc = 1;
            } else {
                rc = apply_ratio_list(&p_list, (uint8_t)ratio);
            }
        } else if (strcmp(argv[1], "--set-e-ratio") == 0) {
            if (e_list.count == 0) {
                fprintf(stderr, "No E cores detected\n");
                rc = 1;
            } else {
                rc = apply_ratio_list(&e_list, (uint8_t)ratio);
            }
        } else {
            if (apply_ratio_list(&p_list, (uint8_t)ratio) != 0) {
                rc = 1;
            }
            if (apply_ratio_list(&e_list, (uint8_t)ratio) != 0) {
                rc = 1;
            }
            if (apply_ratio_list(&u_list, (uint8_t)ratio) != 0) {
                rc = 1;
            }
        }

        cpu_list_free(&p_list);
        cpu_list_free(&e_list);
        cpu_list_free(&u_list);

        if (rc != 0) {
            fprintf(stderr, "Failed to apply ratio\n");
            return 1;
        }
        printf("OK\n");
        return 0;
    }

    if (strcmp(argv[1], "--set-pe-ratio") == 0) {
        if (argc < 4) {
            usage(argv[0]);
            return 2;
        }
        int ratio_p = 0;
        int ratio_e = 0;
        if (!parse_int(argv[2], &ratio_p) || !parse_int(argv[3], &ratio_e) ||
            ratio_p <= 0 || ratio_p > 255 || ratio_e <= 0 || ratio_e > 255) {
            fprintf(stderr, "Invalid ratio values\n");
            return 2;
        }

        struct cpu_list p_list;
        struct cpu_list e_list;
        struct cpu_list u_list;
        cpu_list_init(&p_list);
        cpu_list_init(&e_list);
        cpu_list_init(&u_list);
        if (enumerate_cpus(&p_list, &e_list, &u_list, NULL) != 0) {
            fprintf(stderr, "Failed to enumerate CPUs\n");
            cpu_list_free(&p_list);
            cpu_list_free(&e_list);
            cpu_list_free(&u_list);
            return 1;
        }

        int rc = 0;
        if (p_list.count == 0) {
            fprintf(stderr, "No P cores detected\n");
            rc = 1;
        } else if (apply_ratio_list(&p_list, (uint8_t)ratio_p) != 0) {
            rc = 1;
        }
        if (e_list.count == 0) {
            fprintf(stderr, "No E cores detected\n");
            rc = 1;
        } else if (apply_ratio_list(&e_list, (uint8_t)ratio_e) != 0) {
            rc = 1;
        }

        cpu_list_free(&p_list);
        cpu_list_free(&e_list);
        cpu_list_free(&u_list);

        if (rc != 0) {
            fprintf(stderr, "Failed to apply ratio\n");
            return 1;
        }
        printf("OK\n");
        return 0;
    }

    if (strcmp(argv[1], "--set-core-uv") == 0) {
        if (argc < 3) {
            usage(argv[0]);
            return 2;
        }
        double mv = 0.0;
        if (!parse_double(argv[2], &mv)) {
            fprintf(stderr, "Invalid voltage offset: %s\n", argv[2]);
            return 2;
        }
        if (mv < -500.0 || mv > 500.0) {
            fprintf(stderr, "Refusing voltage offset outside [-500, 500] mV.\n");
            return 2;
        }

        int msr_fd = open_msr(true);
        if (msr_fd < 0) {
            fprintf(stderr, "open(/dev/cpu/0/msr) failed: %s\n", strerror(errno));
            return 1;
        }

        uint32_t raw = oc_encode_offset_mv(mv);
        if (oc_mailbox_write(msr_fd, OC_PLANE_CORE, raw) != 0) {
            fprintf(stderr, "write OC mailbox failed: %s\n", strerror(errno));
            close(msr_fd);
            return 1;
        }

        close(msr_fd);
        printf("OK\n");
        return 0;
    }

    usage(argv[0]);
    return 2;
}
