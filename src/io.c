#define _GNU_SOURCE
/* The linker's file access: ranged reads straight into a worker's data
   stack. A file descriptor is a plain integer, valid in every thread, so
   main opens each input once and any worker reads any range of it. */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <malloc.h>
#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "goose.h"

typedef struct { const uint8_t *data; int64_t len; } ld_bytes;

// Every queue message is a malloc, and a link sends tens of megabytes of
// them from many threads at once: each thread's heap then grows by 64 MB at
// a time rather than page by page, each step of which takes the lock that
// page faults take too (12 ms of a 2,266-object link).
void ld_malloc_setup(void) {
    mallopt(M_TOP_PAD, 64 << 20);
}

// Every input stays open for the whole link, more than the usual soft
// limit of 1024 for a large one: on running out, the soft limit is raised
// to the hard one, once, as mold and wild do at start.
// Grows the file descriptor table to hold n, raising the limit if need be.
// Called while the process has one thread: with more, growing the table
// waits for an RCU grace period, 10 to 15 ms, each time it doubles past 64.
void ld_reserve_fds(int32_t n) {
    struct rlimit r;
    if (getrlimit(RLIMIT_NOFILE, &r) == 0 && r.rlim_cur < (rlim_t)n && r.rlim_cur < r.rlim_max) {
        r.rlim_cur = r.rlim_max < (rlim_t)n ? r.rlim_max : (rlim_t)n;
        setrlimit(RLIMIT_NOFILE, &r);
    }
    int fd = fcntl(0, F_DUPFD_CLOEXEC, n - 1);
    if (fd < 0) fd = fcntl(1, F_DUPFD_CLOEXEC, n - 1);
    if (fd >= 0) close(fd);
}

int32_t ld_open(ld_bytes path) {
    static int raised;
    char p[PATH_MAX];
    if (path.len <= 0 || path.len >= PATH_MAX) return -1;
    memcpy(p, path.data, (size_t)path.len);
    p[path.len] = 0;
    int fd = open(p, O_RDONLY | O_CLOEXEC);
    if (fd < 0 && errno == EMFILE && !raised) {
        struct rlimit r;
        raised = 1;
        if (getrlimit(RLIMIT_NOFILE, &r) == 0 && r.rlim_cur < r.rlim_max) {
            r.rlim_cur = r.rlim_max;
            if (setrlimit(RLIMIT_NOFILE, &r) == 0) fd = open(p, O_RDONLY | O_CLOEXEC);
        }
    }
    return fd;
}

/* Opening the inputs ahead (ld_open_all): each a record of fd (-1 if it
   could not be opened, or is not a regular file), the length of its head,
   its size, and its first head bytes. */
typedef struct {
    const uint8_t *names;      /* the paths, each ended with a 0 */
    int64_t *starts;
    uint8_t *records;
    int64_t n, head, size;     /* records, head bytes, a record's size */
    int64_t next;              /* the next to open, taken atomically */
} ld_ahead;

static void open_one(ld_ahead *a, int64_t i) {
    uint8_t *r = a->records + i * a->size;
    int32_t fd = open((const char *)a->names + a->starts[i], O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    int32_t head_len = 0;
    int64_t size = 0;
    struct stat st;
    if (fd >= 0 && (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode))) { close(fd); fd = -1; }
    if (fd >= 0) {
        size = (int64_t)st.st_size;
        int64_t want = size < a->head ? size : a->head;
        if (want > 0 && pread(fd, r + 16, (size_t)want, 0) != (ssize_t)want) { close(fd); fd = -1; }
        else head_len = (int32_t)want;
    }
    memcpy(r, &fd, 4);
    memcpy(r + 4, &head_len, 4);
    memcpy(r + 8, &size, 8);
}

static void *open_some(void *arg) {
    ld_ahead *a = arg;
    for (;;) {
        int64_t i = __atomic_fetch_add(&a->next, 1, __ATOMIC_RELAXED);
        if (i >= a->n) return NULL;
        open_one(a, i);
    }
}

/* Opens every path in names (each ended with a 0) at once, on a few
   threads of its own, and appends a record for each to out: its fd (-1 if
   it could not be opened or is not a regular file, which O_NONBLOCK keeps
   a FIFO from holding up), the length of its head, its size, and its
   first head bytes. Opening 1,940 inputs one after another took main 10
   to 12 ms of a 1,940-input link before any other thread ran. Called while the
   process has one thread, so that it can grow the descriptor table first
   (ld_reserve_fds). */
void ld_open_all(ld_bytes names, int64_t n, int64_t head, gs_rref out) {
    if (n <= 0) return;
    ld_reserve_fds((int32_t)(n + 256));
    ld_ahead a = { names.data, malloc(sizeof(int64_t) * (size_t)n), NULL, n, head, 16 + head, 0 };
    if (!a.starts) return;
    int64_t at = 0;
    for (int64_t i = 0; i < n; i++) {
        a.starts[i] = at;
        while (at < names.len && names.data[at]) at++;
        at++;
    }
    a.records = out.stk->top;
    memset(a.records, 0, (size_t)(n * a.size));
    int nthreads = n < 1024 ? 4 : 8;
    pthread_t threads[8];
    int started = 0;
    for (int k = 1; k < nthreads; k++)
        if (pthread_create(&threads[started], NULL, open_some, &a) == 0) started++;
    open_some(&a);
    for (int k = 0; k < started; k++) pthread_join(threads[k], NULL);
    free(a.starts);
    out.stk->top += n * a.size;
    out.hdr->len += n * a.size;
}

int64_t ld_file_size(int32_t fd) {
    struct stat st;
    return fstat(fd, &st) == 0 ? (int64_t)st.st_size : -1;
}

/* Appends the size bytes at offset to out; nothing, and 0, unless all of
   them were read. */
uint8_t ld_pread(int32_t fd, int64_t offset, int64_t size, gs_rref out) {
    uint8_t *dst = out.stk->top;
    /* A large read lands on memory not touched yet, the first time: in
       huge pages that is a few faults, not one per 4 KB. */
    #ifdef MADV_HUGEPAGE
    if (size >= (4 << 20)) {
        uintptr_t lo = ((uintptr_t)dst + (2u << 20) - 1) & ~(uintptr_t)((2u << 20) - 1);
        uintptr_t hi = ((uintptr_t)dst + (uintptr_t)size) & ~(uintptr_t)((2u << 20) - 1);
        if (hi > lo) madvise((void *)lo, hi - lo, MADV_HUGEPAGE);
    }
    #endif
    int64_t done = 0;
    while (done < size) {
        ssize_t n = pread(fd, dst + done, (size_t)(size - done), (off_t)(offset + done));
        if (n <= 0) return 0;
        done += n;
    }
    out.stk->top += size;
    out.hdr->len += size;
    return 1;
}

/* The output, mapped: every thread writes into it with memcpy rather than
   a system call per section. */
static int32_t out_fd = -1;
static uint8_t *out_map;
static int64_t out_size;       /* the output's size, which writes must stay within */
static int64_t out_mapped;     /* and the mapping's, which may be larger (ld_create_early) */
static char out_path[PATH_MAX];
static int out_early;          /* made by ld_create_early, not yet given its size */

/* Removing a large old output frees its pages, which takes milliseconds:
   it is renamed out of the way when the link starts, and removed on a
   thread of its own while the link runs; ld_finish waits for that. */
static pthread_t remover;
static int removing;
static char old_path[PATH_MAX + 32];

static void *remove_old(void *arg) {
    (void)arg;
    unlink(old_path);
    return NULL;
}

void ld_remove_old(ld_bytes path) {
    char p[PATH_MAX];
    if (removing || path.len <= 0 || path.len >= PATH_MAX) return;
    memcpy(p, path.data, (size_t)path.len);
    p[path.len] = 0;
    snprintf(old_path, sizeof old_path, "%s.ld-old-%ld", p, (long)getpid());
    if (rename(p, old_path) != 0) return;        /* none there, or not ours to move */
    removing = pthread_create(&remover, NULL, remove_old, NULL) == 0;
    if (!removing) unlink(old_path);
}

void ld_finish(void) {
    if (removing) { pthread_join(remover, NULL); removing = 0; }
}

/* A new file of size bytes, zeros until written, mapped readable and
   writable for every thread: the output. Executable where the umask
   allows. Its blocks allocated at once, as wild does on ext4 and XFS: a
   page's first write then faults it in for less (a 210 MB output written by
   13 threads, 55 to 48 ms). Where the file system cannot, it does not. */
static int32_t create_output(const char *p, int64_t size) {
    unlink(p);       /* a running copy of the old output keeps its own file */
    int fd = open(p, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0777);
    if (fd < 0) return -1;
    if (ftruncate(fd, (off_t)size) != 0) { close(fd); return -1; }
    if (size > 0) (void)fallocate(fd, 0, 0, (off_t)size);
    void *m = size > 0 ? mmap(NULL, (size_t)size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0) : MAP_FAILED;
    if (m != MAP_FAILED) { out_fd = fd; out_map = m; out_size = size; out_mapped = size; }
    return fd;
}

/* The output, before its size is known, at most bound bytes: made while
   main lays the output out, so that the idle workers can fault its pages
   in meanwhile (ld_populate), which writing them would otherwise do, a
   page at a time, while relocating. -1 if it cannot be made. */
int32_t ld_create_early(ld_bytes path, int64_t bound) {
    if (path.len <= 0 || path.len >= PATH_MAX || bound <= 0) return -1;
    memcpy(out_path, path.data, (size_t)path.len);
    out_path[path.len] = 0;
    int32_t fd = create_output(out_path, bound);
    out_early = fd >= 0 && out_fd == fd;
    return fd;
}

/* The output at last, of size bytes: the early one cut to size if it is no
   larger than its bound, else made anew. */
int32_t ld_create(ld_bytes path, int64_t size) {
    if (out_early) {
        out_early = 0;
        if (size <= out_mapped && ftruncate(out_fd, (off_t)size) == 0) { out_size = size; return out_fd; }
        munmap(out_map, (size_t)out_mapped);
        close(out_fd);
        out_fd = -1;
        out_map = NULL;
    }
    char p[PATH_MAX];
    if (path.len <= 0 || path.len >= PATH_MAX) return -1;
    memcpy(p, path.data, (size_t)path.len);
    p[path.len] = 0;
    return create_output(p, size);
}

/* Faults in the output's pages at offset, size bytes of them, for writing
   (a worker's job while main lays out). */
void ld_populate(int64_t offset, int64_t size) {
    #ifndef MADV_POPULATE_WRITE
    #define MADV_POPULATE_WRITE 23
    #endif
    uint8_t *m = out_map;
    int64_t n = out_mapped;
    if (!m || offset < 0 || size <= 0 || offset >= n) return;
    if (size > n - offset) size = n - offset;
    madvise(m + offset, (size_t)size, MADV_POPULATE_WRITE);
}

/* An early output given up on, the link having failed: removed. */
void ld_discard(void) {
    if (!out_early) return;
    out_early = 0;
    munmap(out_map, (size_t)out_mapped);
    close(out_fd);
    out_fd = -1;
    out_map = NULL;
    unlink(out_path);
}

uint8_t ld_pwrite(int32_t fd, int64_t offset, ld_bytes data) {
    if (data.len == 0) return 1;     /* an empty section's, placed past the file's end */
    if (fd == out_fd) {
        if (offset < 0 || data.len > out_size - offset) return 0;
        memcpy(out_map + offset, data.data, (size_t)data.len);
        return 1;
    }
    int64_t done = 0;
    while (done < data.len) {
        ssize_t n = pwrite(fd, data.data + done, (size_t)(data.len - done), (off_t)(offset + done));
        if (n <= 0) return 0;
        done += n;
    }
    return 1;
}

/* Asks for the next n bytes of a worker's buffer to come in huge pages,
   which its reads then fill with a few faults rather than one per 4 KB. */
void ld_prefer_huge(gs_rref buf, int64_t n) {
    #ifdef MADV_HUGEPAGE
    uintptr_t lo = ((uintptr_t)buf.stk->top + (2u << 20) - 1) & ~(uintptr_t)((2u << 20) - 1);
    uintptr_t hi = ((uintptr_t)buf.stk->top + (uintptr_t)n) & ~(uintptr_t)((2u << 20) - 1);
    if (hi > lo) madvise((void *)lo, hi - lo, MADV_HUGEPAGE);
    #else
    (void)buf; (void)n;
    #endif
}

/* Exiting from a large link takes tens of milliseconds: unmapping the
   workers' buffers and data stacks, removing the old output. As mold and
   wild do, weld forks before it starts any thread; the parent waits for one
   byte through a pipe, which the child sends once the output is complete
   and closed, and then exits at once. Without the byte (the link failed, or
   the child died) the parent takes the child's exit status as its own. */
static int notify_fd = -1;

void ld_fork(void) {
    int fds[2];
    if (pipe(fds) != 0) return;                  /* then no fork: link as one process */
    fflush(NULL);
    pid_t pid = fork();
    if (pid < 0) { close(fds[0]); close(fds[1]); return; }
    if (pid > 0) {
        close(fds[1]);
        char c;
        ssize_t n;
        do { n = read(fds[0], &c, 1); } while (n < 0 && errno == EINTR);
        if (n == 1) _exit(0);
        int status;
        while (waitpid(pid, &status, 0) < 0) { if (errno != EINTR) _exit(1); }
        if (WIFEXITED(status)) _exit(WEXITSTATUS(status));
        if (WIFSIGNALED(status)) { signal(WTERMSIG(status), SIG_DFL); raise(WTERMSIG(status)); }
        _exit(1);
    }
    close(fds[0]);
    notify_fd = fds[1];
}

/* Tells the parent the link succeeded, after the output's last byte and
   its close (an executable still open for writing would not run). What
   the child prints after that goes nowhere: a build system reading the
   linker's output waits for the pipe to close, not only for the parent. */
void ld_notify(void) {
    if (notify_fd < 0) return;
    fflush(NULL);
    char c = 1;
    ssize_t n;
    do { n = write(notify_fd, &c, 1); } while (n < 0 && errno == EINTR);
    close(notify_fd);
    notify_fd = -1;
    int null = open("/dev/null", O_WRONLY);
    if (null >= 0) { dup2(null, 1); dup2(null, 2); close(null); }
}

void ld_close(int32_t fd) {
    if (fd == out_fd) { munmap(out_map, (size_t)out_mapped); out_fd = -1; out_map = NULL; }
    close(fd);
}
