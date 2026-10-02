#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define OUTER_HEADER_LEN 44U
#define OUTER_MAX_PAYLOAD 65536U
#define OUTER_VERSION 1U
#define OUTER_GUEST_ATTACH 1U
#define OUTER_RESET 3U
#define OUTER_ACK 4U
#define OUTER_DATA 5U
#define OUTER_CREDIT 9U
#define OUTER_RECEIVE_WINDOW (1024U * 1024U)

#define APP_HEADER_LEN 24U
#define APP_VERSION 1U
#define APP_PING 1U
#define APP_EXEC 2U
#define APP_STOP 3U
#define APP_READY 0x81U
#define APP_STDOUT 0x82U
#define APP_STDERR 0x83U
#define APP_EXIT 0x84U
#define APP_STOPPED 0x85U
#define APP_ERROR 0xffU

#define MAX_ARGUMENTS 64U
#define MAX_ARGUMENT_LEN 4096U
#define MAX_ENVIRONMENT 256U
#define EXEC_EXTENDED 1U
#define EXEC_CWD_PRESENT 1U
#define EXEC_ENVIRONMENT_PRESENT 2U
#define MAX_OUTPUT_BYTES (1024U * 1024U)
#define OUTPUT_CHUNK_BYTES 32768U
#define CONTAINER_BARRIER_ATTEMPTS 500U
#define PORTB_CONSOLE 0xe9
#define AGENT_STOPPED 1

struct outer_record {
    uint8_t type;
    uint8_t instance_id[16];
    uint64_t epoch;
    uint64_t sequence;
    uint32_t payload_len;
    uint8_t *payload;
};

struct control_session {
    int fd;
    uint8_t instance_id[16];
    uint64_t epoch;
    uint64_t guest_sequence;
    uint64_t host_sequence;
};

struct app_request {
    uint8_t kind;
    uint64_t request_id;
    int32_t status;
    uint32_t payload_len;
    const uint8_t *payload;
};

struct agent_config {
    const char *rootfs;
    const char *hostname;
    const char *uid;
    const char *gid;
    const char *user;
    const char *home;
    int direct;
};

struct exec_config {
    char *cwd;
    char **environment;
    uint16_t environment_count;
    int environment_present;
};

static uint16_t read_u16(const uint8_t *bytes)
{
    return (uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8);
}

static uint32_t read_u32(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static uint64_t read_u64(const uint8_t *bytes)
{
    uint64_t value = 0;
    unsigned int index;

    for (index = 0; index < 8; ++index) {
        value |= (uint64_t)bytes[index] << (index * 8);
    }
    return value;
}

static void write_u16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
}

static void write_u32(uint8_t *bytes, uint32_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)(value >> 16);
    bytes[3] = (uint8_t)(value >> 24);
}

static void write_u64(uint8_t *bytes, uint64_t value)
{
    unsigned int index;

    for (index = 0; index < 8; ++index) {
        bytes[index] = (uint8_t)(value >> (index * 8));
    }
}

static int read_exact(int fd, void *buffer, size_t length)
{
    uint8_t *bytes = buffer;
    size_t offset = 0;

    while (offset < length) {
        ssize_t count = read(fd, bytes + offset, length - offset);
        if (count > 0) {
            offset += (size_t)count;
        } else if (count == 0) {
            return -1;
        } else if (errno != EINTR) {
            return -1;
        }
    }
    return 0;
}

static int write_all(int fd, const void *buffer, size_t length)
{
    const uint8_t *bytes = buffer;
    size_t offset = 0;

    while (offset < length) {
        ssize_t count = write(fd, bytes + offset, length - offset);
        if (count > 0) {
            offset += (size_t)count;
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            return -1;
        }
    }
    return 0;
}

static void portb_log(const char *message)
{
    int fd = open("/dev/port", O_WRONLY | O_CLOEXEC);

    if (fd < 0) {
        return;
    }
    while (*message != '\0') {
        if (pwrite(fd, message, 1, PORTB_CONSOLE) != 1) {
            break;
        }
        ++message;
    }
    close(fd);
}

static void portb_error(const char *stage, int status)
{
    char message[128];
    int length = snprintf(
        message,
        sizeof(message),
        "NVX-MANAGED-ERROR: stage=%s status=%d\n",
        stage,
        status);

    if (length > 0 && (size_t)length < sizeof(message)) {
        portb_log(message);
    }
}

static void free_outer_record(struct outer_record *record)
{
    free(record->payload);
    record->payload = NULL;
    record->payload_len = 0;
}

static int read_outer_record(int fd, struct outer_record *record)
{
    uint8_t header[OUTER_HEADER_LEN];

    memset(record, 0, sizeof(*record));
    if (read_exact(fd, header, sizeof(header)) != 0) {
        return -1;
    }
    if (memcmp(header, "NVXS", 4) != 0 || read_u16(header + 4) != OUTER_VERSION ||
        header[7] != 0) {
        return -1;
    }
    record->type = header[6];
    memcpy(record->instance_id, header + 8, sizeof(record->instance_id));
    record->epoch = read_u64(header + 24);
    record->sequence = read_u64(header + 32);
    record->payload_len = read_u32(header + 40);
    if (record->payload_len > OUTER_MAX_PAYLOAD) {
        return -1;
    }
    if (record->payload_len != 0) {
        record->payload = malloc(record->payload_len);
        if (record->payload == NULL ||
            read_exact(fd, record->payload, record->payload_len) != 0) {
            free_outer_record(record);
            return -1;
        }
    }
    return 0;
}

static int write_outer_record(
    int fd,
    uint8_t type,
    const uint8_t instance_id[16],
    uint64_t epoch,
    uint64_t sequence,
    const void *payload,
    uint32_t payload_len)
{
    uint8_t header[OUTER_HEADER_LEN] = {0};

    if (payload_len > OUTER_MAX_PAYLOAD) {
        return -1;
    }
    memcpy(header, "NVXS", 4);
    write_u16(header + 4, OUTER_VERSION);
    header[6] = type;
    memcpy(header + 8, instance_id, 16);
    write_u64(header + 24, epoch);
    write_u64(header + 32, sequence);
    write_u32(header + 40, payload_len);
    if (write_all(fd, header, sizeof(header)) != 0) {
        return -1;
    }
    return payload_len == 0 || write_all(fd, payload, payload_len) == 0 ? 0 : -1;
}

static int send_guest_attach(int fd)
{
    const uint8_t zero_instance[16] = {0};

    return write_outer_record(
        fd, OUTER_GUEST_ATTACH, zero_instance, 0, 0, NULL, 0);
}

static int acknowledge_reset(
    struct control_session *session,
    const struct outer_record *record)
{
    uint8_t credit[4];

    if (record->type != OUTER_RESET || record->payload_len != 0 ||
        record->epoch == 0) {
        return -1;
    }
    memcpy(session->instance_id, record->instance_id, 16);
    session->epoch = record->epoch;
    session->guest_sequence = 0;
    session->host_sequence = record->sequence + 1;
    write_u32(credit, OUTER_RECEIVE_WINDOW);
    if (write_outer_record(
            session->fd,
            OUTER_ACK,
            session->instance_id,
            session->epoch,
            session->guest_sequence,
            credit,
            sizeof(credit)) != 0) {
        return -1;
    }
    session->guest_sequence = 1;
    return 0;
}

static int send_guest_record(
    struct control_session *session,
    uint8_t type,
    const void *payload,
    uint32_t payload_len)
{
    if (write_outer_record(
            session->fd,
            type,
            session->instance_id,
            session->epoch,
            session->guest_sequence,
            payload,
            payload_len) != 0) {
        return -1;
    }
    ++session->guest_sequence;
    return 0;
}

static int send_credit(struct control_session *session, uint32_t bytes)
{
    uint8_t payload[4];

    if (bytes == 0) {
        return 0;
    }
    write_u32(payload, bytes);
    return send_guest_record(session, OUTER_CREDIT, payload, sizeof(payload));
}

static int send_app_frame(
    struct control_session *session,
    uint8_t kind,
    uint64_t request_id,
    int32_t status,
    const void *payload,
    uint32_t payload_len)
{
    uint8_t *frame;
    uint32_t frame_len;
    int result;

    if (payload_len > OUTER_MAX_PAYLOAD - APP_HEADER_LEN) {
        return -1;
    }
    frame_len = APP_HEADER_LEN + payload_len;
    frame = malloc(frame_len);
    if (frame == NULL) {
        return -1;
    }
    memset(frame, 0, APP_HEADER_LEN);
    memcpy(frame, "NVXC", 4);
    frame[4] = APP_VERSION;
    frame[5] = kind;
    write_u64(frame + 8, request_id);
    write_u32(frame + 16, (uint32_t)status);
    write_u32(frame + 20, payload_len);
    if (payload_len != 0) {
        memcpy(frame + APP_HEADER_LEN, payload, payload_len);
    }
    result = send_guest_record(session, OUTER_DATA, frame, frame_len);
    free(frame);
    return result;
}

static int parse_app_request(
    const uint8_t *payload,
    uint32_t payload_len,
    struct app_request *request)
{
    uint32_t declared_len;

    if (payload_len < APP_HEADER_LEN || memcmp(payload, "NVXC", 4) != 0 ||
        payload[4] != APP_VERSION || read_u16(payload + 6) != 0) {
        return -1;
    }
    declared_len = read_u32(payload + 20);
    if (declared_len != payload_len - APP_HEADER_LEN) {
        return -1;
    }
    request->kind = payload[5];
    request->request_id = read_u64(payload + 8);
    request->status = (int32_t)read_u32(payload + 16);
    request->payload_len = declared_len;
    request->payload = payload + APP_HEADER_LEN;
    return request->request_id != 0 && request->status == 0 ? 0 : -1;
}

static int send_app_error(
    struct control_session *session,
    uint64_t request_id,
    int32_t status,
    const char *category)
{
    return send_app_frame(
        session,
        APP_ERROR,
        request_id,
        status,
        category,
        (uint32_t)strlen(category));
}

static uint64_t monotonic_milliseconds(void)
{
    struct timespec value;

    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) {
        return 0;
    }
    return (uint64_t)value.tv_sec * 1000U + (uint64_t)value.tv_nsec / 1000000U;
}

static int open_control_tty(const char *path)
{
    const struct timespec delay = {
        .tv_sec = 0,
        .tv_nsec = 50U * 1000U * 1000U,
    };
    unsigned int attempt;

    for (attempt = 0; attempt < 600; ++attempt) {
        int fd = open(path, O_RDWR | O_CLOEXEC);
        if (fd >= 0) {
            return fd;
        }
        if (errno != ENOENT && errno != ENXIO && errno != ENODEV && errno != EIO) {
            return -1;
        }
        nanosleep(&delay, NULL);
    }
    errno = ETIMEDOUT;
    return -1;
}

static int configure_control_tty(int fd)
{
    struct termios settings;

    if (tcgetattr(fd, &settings) != 0) {
        return -1;
    }
    cfmakeraw(&settings);
    settings.c_cflag |= CLOCAL;
    return tcsetattr(fd, TCSANOW, &settings);
}

static int make_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL);

    return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 ? 0 : -1;
}

static int write_pid_to_cgroup(pid_t pid)
{
    char buffer[32];
    int fd;
    int length;

    fd = open("/sys/fs/cgroup/container/cgroup.procs", O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    length = snprintf(buffer, sizeof(buffer), "%ld\n", (long)pid);
    if (length <= 0 || (size_t)length >= sizeof(buffer) ||
        write_all(fd, buffer, (size_t)length) != 0) {
        close(fd);
        return -1;
    }
    return close(fd);
}

/* Returns 0 after writing, 1 for an unreaped child exit, or -1 on failure. */
static int release_container_barrier(const char *path, pid_t child)
{
    unsigned int attempt;

    for (attempt = 0; attempt < CONTAINER_BARRIER_ATTEMPTS; ++attempt) {
        int fd = open(path, O_WRONLY | O_CLOEXEC | O_NONBLOCK);

        if (fd >= 0) {
            int result = write_all(fd, "start\n", 6);

            close(fd);
            return result;
        }
        if (errno != ENXIO && errno != EINTR) {
            return -1;
        }
        if (child > 0) {
            siginfo_t information = {0};

            if (waitid(
                    P_PID,
                    (id_t)child,
                    &information,
                    WEXITED | WNOHANG | WNOWAIT) != 0) {
                if (errno == EINTR) {
                    continue;
                }
                return -1;
            }
            if (information.si_pid == child) {
                return 1;
            }
        }
        {
            const struct timespec delay = {.tv_nsec = 10000000L};

            nanosleep(&delay, NULL);
        }
    }
    errno = ETIMEDOUT;
    return -1;
}

static void exec_direct(
    const struct agent_config *config,
    const char *config_fd,
    char *const workload_argv[])
{
    char *arguments[MAX_ARGUMENTS + 20];
    size_t index = 0;
    size_t workload_index = 0;

    if (setenv("HOME", config->home, 1) != 0 ||
        setenv("USER", config->user, 1) != 0 ||
        setenv("LOGNAME", config->user, 1) != 0) {
        dprintf(
            STDERR_FILENO,
            "nvx-managed-agent: cannot configure workload environment: %s\n",
            strerror(errno));
        _exit(125);
    }
    arguments[index++] = "setpriv";
    arguments[index++] = "--reuid";
    arguments[index++] = (char *)config->uid;
    arguments[index++] = "--regid";
    arguments[index++] = (char *)config->gid;
    arguments[index++] = "--clear-groups";
    arguments[index++] = "--no-new-privs";
    arguments[index++] = "--bounding-set=-all";
    arguments[index++] = "--inh-caps=-all";
    arguments[index++] = "--ambient-caps=-all";
    arguments[index++] = "/sbin/nvx-managed-agent";
    arguments[index++] = "--exec-config-fd";
    arguments[index++] = (char *)config_fd;
    arguments[index++] = "--";
    while (workload_argv[workload_index] != NULL && index + 1 < MAX_ARGUMENTS + 20) {
        arguments[index++] = workload_argv[workload_index++];
    }
    arguments[index] = NULL;
    execvp("setpriv", arguments);
    _exit(125);
}

static void exec_sandbox(
    const struct agent_config *config,
    const char *barrier,
    const char *config_fd,
    char *const workload_argv[])
{
    char *arguments[MAX_ARGUMENTS + 10];
    size_t index = 0;
    size_t workload_index = 0;

    arguments[index++] = "/sbin/nvx-container-launch";
    arguments[index++] = (char *)barrier;
    arguments[index++] = (char *)config->rootfs;
    arguments[index++] = (char *)config->hostname;
    arguments[index++] = (char *)config->uid;
    arguments[index++] = (char *)config->gid;
    arguments[index++] = (char *)config->user;
    arguments[index++] = (char *)config->home;
    if (setenv("NVX_EXEC_CONFIG_FD", config_fd, 1) != 0) {
        dprintf(
            STDERR_FILENO,
            "nvx-managed-agent: cannot export execution configuration: %s\n",
            strerror(errno));
        _exit(125);
    }
    while (workload_argv[workload_index] != NULL && index + 1 < MAX_ARGUMENTS + 10) {
        arguments[index++] = workload_argv[workload_index++];
    }
    arguments[index] = NULL;
    execv(arguments[0], arguments);
    _exit(125);
}

static int decode_exec_payload(
    const uint8_t *payload,
    uint32_t payload_len,
    uint32_t *timeout_ms,
    char ***workload_argv,
    struct exec_config *config)
{
    uint16_t argc;
    uint16_t extension;
    uint16_t flags = 0;
    uint16_t environment_count = 0;
    uint32_t cwd_len = 0;
    uint32_t offset = 8;
    char **arguments;
    uint16_t index;

    if (payload_len < 8) {
        return -1;
    }
    *timeout_ms = read_u32(payload);
    argc = read_u16(payload + 4);
    extension = read_u16(payload + 6);
    if (argc == 0 || argc > MAX_ARGUMENTS) {
        return -1;
    }
    if (extension == EXEC_EXTENDED) {
        if (payload_len < 16) {
            return -1;
        }
        flags = read_u16(payload + 8);
        environment_count = read_u16(payload + 10);
        cwd_len = read_u32(payload + 12);
        offset = 16;
        if ((flags & ~(EXEC_CWD_PRESENT | EXEC_ENVIRONMENT_PRESENT)) != 0 ||
            ((flags & EXEC_CWD_PRESENT) == 0 && cwd_len != 0) ||
            ((flags & EXEC_CWD_PRESENT) != 0 &&
             (cwd_len == 0 || cwd_len > MAX_ARGUMENT_LEN)) ||
            ((flags & EXEC_ENVIRONMENT_PRESENT) == 0 &&
             environment_count != 0) ||
            environment_count > MAX_ENVIRONMENT) {
            return -1;
        }
    } else if (extension != 0) {
        return -1;
    }
    arguments = calloc((size_t)argc + 1, sizeof(*arguments));
    if (arguments == NULL) {
        return -1;
    }
    for (index = 0; index < argc; ++index) {
        uint32_t length;

        if (offset > payload_len || payload_len - offset < 4) {
            goto fail;
        }
        length = read_u32(payload + offset);
        offset += 4;
        if (length == 0 || length > MAX_ARGUMENT_LEN || length > payload_len - offset ||
            memchr(payload + offset, '\0', length) != NULL) {
            goto fail;
        }
        arguments[index] = malloc((size_t)length + 1);
        if (arguments[index] == NULL) {
            goto fail;
        }
        memcpy(arguments[index], payload + offset, length);
        arguments[index][length] = '\0';
        offset += length;
    }
    if (arguments[0][0] != '/' ||
        (extension == 0 && offset != payload_len)) {
        goto fail;
    }
    if (extension == EXEC_EXTENDED) {
        if (cwd_len != 0) {
            if (cwd_len > payload_len - offset ||
                memchr(payload + offset, '\0', cwd_len) != NULL ||
                payload[offset] != '/') {
                goto fail;
            }
            config->cwd = malloc((size_t)cwd_len + 1);
            if (config->cwd == NULL) {
                goto fail;
            }
            memcpy(config->cwd, payload + offset, cwd_len);
            config->cwd[cwd_len] = '\0';
            offset += cwd_len;
        }
        if ((flags & EXEC_ENVIRONMENT_PRESENT) != 0) {
            config->environment = calloc(
                (size_t)environment_count + 1, sizeof(*config->environment));
            if (config->environment == NULL) {
                goto fail;
            }
            config->environment_present = 1;
            config->environment_count = environment_count;
            for (index = 0; index < environment_count; ++index) {
                uint32_t length;
                const uint8_t *equals;

                if (offset > payload_len || payload_len - offset < 4) {
                    goto fail;
                }
                length = read_u32(payload + offset);
                offset += 4;
                if (length == 0 || length > MAX_ARGUMENT_LEN ||
                    length > payload_len - offset ||
                    memchr(payload + offset, '\0', length) != NULL) {
                    goto fail;
                }
                equals = memchr(payload + offset, '=', length);
                if (equals == NULL || equals == payload + offset) {
                    goto fail;
                }
                for (uint16_t previous = 0; previous < index; ++previous) {
                    size_t name_length = (size_t)(equals - (payload + offset));
                    const char *prior = config->environment[previous];
                    if (strcspn(prior, "=") == name_length &&
                        memcmp(prior, payload + offset, name_length) == 0) {
                        goto fail;
                    }
                }
                config->environment[index] = malloc((size_t)length + 1);
                if (config->environment[index] == NULL) {
                    goto fail;
                }
                memcpy(config->environment[index], payload + offset, length);
                config->environment[index][length] = '\0';
                offset += length;
            }
        }
        if (offset != payload_len) {
            goto fail;
        }
    }
    *workload_argv = arguments;
    return 0;

fail:
    for (index = 0; index < argc; ++index) {
        free(arguments[index]);
    }
    free(arguments);
    free(config->cwd);
    config->cwd = NULL;
    if (config->environment != NULL) {
        for (index = 0; index < config->environment_count; ++index) {
            free(config->environment[index]);
        }
        free(config->environment);
        config->environment = NULL;
    }
    return -1;
}

static void free_arguments(char **arguments)
{
    size_t index;

    if (arguments == NULL) {
        return;
    }
    for (index = 0; arguments[index] != NULL; ++index) {
        free(arguments[index]);
    }
    free(arguments);
}

static void free_exec_config(struct exec_config *config)
{
    uint16_t index;

    free(config->cwd);
    for (index = 0; index < config->environment_count; ++index) {
        free(config->environment[index]);
    }
    free(config->environment);
    memset(config, 0, sizeof(*config));
}

static int write_exec_config(int fd, const struct exec_config *config)
{
    uint8_t header[8];
    uint16_t flags = 0;
    uint16_t index;

    if (config->cwd != NULL) {
        flags |= EXEC_CWD_PRESENT;
    }
    if (config->environment_present) {
        flags |= EXEC_ENVIRONMENT_PRESENT;
    }
    write_u16(header, flags);
    write_u16(header + 2, config->environment_count);
    write_u32(header + 4, config->cwd == NULL ? 0 : (uint32_t)strlen(config->cwd));
    if (write_all(fd, header, sizeof(header)) != 0 ||
        (config->cwd != NULL &&
         write_all(fd, config->cwd, strlen(config->cwd)) != 0)) {
        return -1;
    }
    for (index = 0; index < config->environment_count; ++index) {
        uint32_t length = (uint32_t)strlen(config->environment[index]);
        uint8_t encoded_length[4];

        write_u32(encoded_length, length);
        if (write_all(fd, encoded_length, sizeof(encoded_length)) != 0 ||
            write_all(fd, config->environment[index], length) != 0) {
            return -1;
        }
    }
    return 0;
}

static int create_exec_config_fd(const struct exec_config *config)
{
    int fd = memfd_create("nvx-exec-config", MFD_CLOEXEC | MFD_ALLOW_SEALING);

    if (fd < 0) {
        return -1;
    }
    /* A sealed, bounded anonymous file avoids depending on pipe capacity. */
    if (write_exec_config(fd, config) != 0 ||
        lseek(fd, 0, SEEK_SET) < 0 ||
        fcntl(fd, F_ADD_SEALS,
              F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int launch_workload(int argc, char **argv)
{
    char *end = NULL;
    long descriptor;
    uint8_t header[8];
    uint16_t flags;
    uint16_t environment_count;
    uint32_t cwd_len;
    char *cwd = NULL;
    char **environment = NULL;
    uint16_t index;

    if (argc < 5 || strcmp(argv[1], "--exec-config-fd") != 0 ||
        strcmp(argv[3], "--") != 0 || argv[4][0] != '/') {
        return 125;
    }
    errno = 0;
    descriptor = strtol(argv[2], &end, 10);
    if (errno != 0 || end == argv[2] || *end != '\0' ||
        descriptor < 0 || descriptor > INT32_MAX ||
        read_exact((int)descriptor, header, sizeof(header)) != 0) {
        return 125;
    }
    flags = read_u16(header);
    environment_count = read_u16(header + 2);
    cwd_len = read_u32(header + 4);
    if ((flags & ~(EXEC_CWD_PRESENT | EXEC_ENVIRONMENT_PRESENT)) != 0 ||
        environment_count > MAX_ENVIRONMENT ||
        ((flags & EXEC_CWD_PRESENT) == 0 && cwd_len != 0) ||
        ((flags & EXEC_CWD_PRESENT) != 0 &&
         (cwd_len == 0 || cwd_len > MAX_ARGUMENT_LEN)) ||
        ((flags & EXEC_ENVIRONMENT_PRESENT) == 0 &&
         environment_count != 0)) {
        return 125;
    }
    if (cwd_len != 0) {
        cwd = malloc((size_t)cwd_len + 1);
        if (cwd == NULL || read_exact((int)descriptor, cwd, cwd_len) != 0) {
            free(cwd);
            return 125;
        }
        cwd[cwd_len] = '\0';
    }
    environment = calloc(
        (size_t)environment_count + 1, sizeof(*environment));
    if (environment == NULL) {
        free(cwd);
        return 125;
    }
    for (index = 0; index < environment_count; ++index) {
        uint8_t encoded_length[4];
        uint32_t length;

        if (read_exact((int)descriptor, encoded_length, 4) != 0) {
            goto fail;
        }
        length = read_u32(encoded_length);
        if (length == 0 || length > MAX_ARGUMENT_LEN) {
            goto fail;
        }
        environment[index] = malloc((size_t)length + 1);
        if (environment[index] == NULL ||
            read_exact((int)descriptor, environment[index], length) != 0) {
            goto fail;
        }
        if (memchr(environment[index], '\0', length) != NULL ||
            environment[index][0] == '=' ||
            memchr(environment[index], '=', length) == NULL) {
            goto fail;
        }
        environment[index][length] = '\0';
    }
    close((int)descriptor);
    if (cwd != NULL &&
        (cwd[0] != '/' || memchr(cwd, '\0', cwd_len) != NULL)) {
        dprintf(STDERR_FILENO, "nvx-managed-agent: invalid working directory\n");
        goto fail;
    }
    if (unsetenv("NVX_EXEC_CONFIG_FD") != 0) {
        goto fail;
    }
    if ((flags & EXEC_ENVIRONMENT_PRESENT) != 0) {
        if (clearenv() != 0) {
            goto fail;
        }
        for (index = 0; index < environment_count; ++index) {
            if (putenv(environment[index]) != 0) {
                goto fail;
            }
            environment[index] = NULL;
        }
    }
    if (chdir(cwd == NULL ? "/" : cwd) != 0) {
        dprintf(
            STDERR_FILENO,
            "nvx-managed-agent: cannot use working directory %s: %s\n",
            cwd == NULL ? "/" : cwd,
            strerror(errno));
        goto fail;
    }
    execv(argv[4], &argv[4]);
    dprintf(
        STDERR_FILENO,
        "nvx-managed-agent: cannot execute workload: %s\n",
        strerror(errno));

fail:
    free(cwd);
    for (index = 0; index < environment_count; ++index) {
        free(environment[index]);
    }
    free(environment);
    return 125;
}

static int stream_output(
    struct control_session *session,
    uint64_t request_id,
    int fd,
    uint8_t kind,
    size_t *output_bytes)
{
    uint8_t buffer[OUTPUT_CHUNK_BYTES];
    ssize_t count;

    for (;;) {
        count = read(fd, buffer, sizeof(buffer));
        if (count > 0) {
            if (*output_bytes > MAX_OUTPUT_BYTES - (size_t)count) {
                return -2;
            }
            *output_bytes += (size_t)count;
            if (send_app_frame(
                    session,
                    kind,
                    request_id,
                    0,
                    buffer,
                    (uint32_t)count) != 0) {
                return -1;
            }
        } else if (count == 0) {
            return 1;
        } else if (errno == EINTR) {
            continue;
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        } else {
            return -1;
        }
    }
}

static int run_exec(
    struct control_session *session,
    const struct agent_config *config,
    uint64_t request_id,
    uint32_t timeout_ms,
    char **workload_argv,
    const struct exec_config *exec_config)
{
    const char *barrier = "/run/nvx/managed-container-start";
    int stdout_pipe[2] = {-1, -1};
    int stderr_pipe[2] = {-1, -1};
    int exec_config_fd = -1;
    pid_t child;
    uint64_t started;
    size_t output_bytes = 0;
    int stdout_open = 1;
    int stderr_open = 1;
    int timed_out = 0;
    int output_limited = 0;
    int wait_status = 0;
    int child_exited = 0;
    int launch_failed = 0;

    if (!config->direct) {
        unlink(barrier);
        if (mkfifo(barrier, 0600) != 0) {
            return send_app_error(session, request_id, 125, "launch-failed");
        }
    }
    if (pipe2(stdout_pipe, O_CLOEXEC) != 0 ||
        pipe2(stderr_pipe, O_CLOEXEC) != 0 ||
        (exec_config_fd = create_exec_config_fd(exec_config)) < 0) {
        unlink(barrier);
        if (stdout_pipe[0] >= 0) {
            close(stdout_pipe[0]);
            close(stdout_pipe[1]);
        }
        if (stderr_pipe[0] >= 0) {
            close(stderr_pipe[0]);
            close(stderr_pipe[1]);
        }
        if (exec_config_fd >= 0) {
            close(exec_config_fd);
        }
        return send_app_error(session, request_id, 125, "launch-failed");
    }

    child = fork();
    if (child < 0) {
        close(stdout_pipe[0]);
        close(stdout_pipe[1]);
        close(stderr_pipe[0]);
        close(stderr_pipe[1]);
        close(exec_config_fd);
        unlink(barrier);
        return send_app_error(session, request_id, 125, "launch-failed");
    }
    if (child == 0) {
        int null_fd;
        char config_fd[32];

        setpgid(0, 0);
        if (fcntl(exec_config_fd, F_SETFD, 0) != 0 ||
            snprintf(
                config_fd, sizeof(config_fd), "%d", exec_config_fd) <= 0) {
            _exit(125);
        }
        close(stdout_pipe[0]);
        close(stderr_pipe[0]);
        null_fd = open("/dev/null", O_RDONLY);
        if (null_fd >= 0) {
            dup2(null_fd, STDIN_FILENO);
            close(null_fd);
        }
        dup2(stdout_pipe[1], STDOUT_FILENO);
        dup2(stderr_pipe[1], STDERR_FILENO);
        close(stdout_pipe[1]);
        close(stderr_pipe[1]);
        if (config->direct) {
            exec_direct(config, config_fd, workload_argv);
        }
        exec_sandbox(config, barrier, config_fd, workload_argv);
    }

    setpgid(child, child);
    close(exec_config_fd);
    close(stdout_pipe[1]);
    close(stderr_pipe[1]);
    launch_failed = make_nonblocking(stdout_pipe[0]) != 0 ||
                    make_nonblocking(stderr_pipe[0]) != 0;
    if (!launch_failed && !config->direct) {
        int barrier_result;

        if (write_pid_to_cgroup(child) != 0) {
            launch_failed = 1;
        } else {
            barrier_result = release_container_barrier(barrier, child);
            launch_failed = barrier_result < 0;
        }
    }
    if (launch_failed) {
        kill(-child, SIGKILL);
        waitpid(child, NULL, 0);
        close(stdout_pipe[0]);
        close(stderr_pipe[0]);
        unlink(barrier);
        return send_app_error(session, request_id, 125, "launch-failed");
    }
    unlink(barrier);
    started = monotonic_milliseconds();

    while (!child_exited || stdout_open || stderr_open) {
        struct pollfd descriptors[2];
        int poll_result;
        int stdout_result = 0;
        int stderr_result = 0;

        descriptors[0].fd = stdout_open ? stdout_pipe[0] : -1;
        descriptors[0].events = POLLIN | POLLHUP;
        descriptors[0].revents = 0;
        descriptors[1].fd = stderr_open ? stderr_pipe[0] : -1;
        descriptors[1].events = POLLIN | POLLHUP;
        descriptors[1].revents = 0;
        poll_result = poll(descriptors, 2, 25);
        if (poll_result < 0 && errno != EINTR) {
            kill(-child, SIGKILL);
        }
        if (stdout_open && descriptors[0].revents != 0) {
            stdout_result = stream_output(
                session, request_id, stdout_pipe[0], APP_STDOUT, &output_bytes);
        }
        if (stderr_open && descriptors[1].revents != 0) {
            stderr_result = stream_output(
                session, request_id, stderr_pipe[0], APP_STDERR, &output_bytes);
        }
        if (stdout_result == 1) {
            close(stdout_pipe[0]);
            stdout_open = 0;
        }
        if (stderr_result == 1) {
            close(stderr_pipe[0]);
            stderr_open = 0;
        }
        if (stdout_result < 0 || stderr_result < 0) {
            output_limited = stdout_result == -2 || stderr_result == -2;
            kill(-child, SIGKILL);
        }
        if (!child_exited) {
            pid_t result = waitpid(child, &wait_status, WNOHANG);
            if (result == child) {
                child_exited = 1;
            } else if (result < 0 && errno != EINTR) {
                kill(-child, SIGKILL);
            }
        }
        if (!child_exited && timeout_ms != 0 &&
            monotonic_milliseconds() - started >= timeout_ms) {
            timed_out = 1;
            kill(-child, SIGKILL);
        }
        if ((timed_out || output_limited) && !child_exited) {
            if (waitpid(child, &wait_status, 0) == child) {
                child_exited = 1;
            }
        }
    }

    if (timed_out) {
        return send_app_frame(
            session, APP_EXIT, request_id, 124, "timeout", 7);
    }
    if (output_limited) {
        return send_app_frame(
            session, APP_EXIT, request_id, 125, "output-limit", 12);
    }
    if (WIFEXITED(wait_status)) {
        return send_app_frame(
            session,
            APP_EXIT,
            request_id,
            WEXITSTATUS(wait_status),
            "exit",
            4);
    }
    if (WIFSIGNALED(wait_status)) {
        int status = 128 + WTERMSIG(wait_status);
        return send_app_frame(
            session, APP_EXIT, request_id, status, "signal", 6);
    }
    return send_app_frame(
        session, APP_EXIT, request_id, 125, "failed", 6);
}

static int handle_data_record(
    struct control_session *session,
    const struct agent_config *config,
    const struct outer_record *record)
{
    struct app_request request;
    char **workload_argv = NULL;
    struct exec_config exec_config = {0};
    uint32_t timeout_ms = 0;
    int result;

    if (record->sequence != session->host_sequence) {
        portb_error("data-sequence", (int)record->sequence);
        return -1;
    }
    if (record->epoch != session->epoch ||
        memcmp(record->instance_id, session->instance_id, 16) != 0) {
        portb_error("data-identity", (int)record->epoch);
        return -1;
    }
    if (parse_app_request(record->payload, record->payload_len, &request) != 0) {
        portb_error("data-application", (int)record->payload_len);
        return -1;
    }
    ++session->host_sequence;
    if (send_credit(session, record->payload_len) != 0) {
        portb_error("data-credit", (int)record->payload_len);
        return -1;
    }

    switch (request.kind) {
    case APP_PING:
        if (request.payload_len != 0) {
            portb_error("ping-payload", (int)request.payload_len);
            return send_app_error(
                session, request.request_id, 22, "invalid-request");
        }
        result = send_app_frame(
            session, APP_READY, request.request_id, 0, NULL, 0);
        if (result != 0) {
            portb_error("ping-ready", errno);
        }
        return result;
    case APP_EXEC:
        if (decode_exec_payload(
                request.payload,
                request.payload_len,
                &timeout_ms,
                &workload_argv,
                &exec_config) != 0) {
            return send_app_error(
                session, request.request_id, 22, "invalid-request");
        }
        result = run_exec(
            session,
            config,
            request.request_id,
            timeout_ms,
            workload_argv,
            &exec_config);
        free_arguments(workload_argv);
        free_exec_config(&exec_config);
        return result;
    case APP_STOP:
        if (request.payload_len != 0 ||
            send_app_frame(
                session, APP_STOPPED, request.request_id, 0, NULL, 0) != 0) {
            return -1;
        }
        tcdrain(session->fd);
        return AGENT_STOPPED;
    default:
        return send_app_error(
            session, request.request_id, 95, "unsupported-operation");
    }
}

static int run_agent(
    struct control_session *session,
    const struct agent_config *config)
{
    struct outer_record record;

    if (send_guest_attach(session->fd) != 0) {
        return -1;
    }
    for (;;) {
        if (read_outer_record(session->fd, &record) != 0) {
            portb_error("outer-read", errno);
            return -1;
        }
        if (record.type == OUTER_RESET) {
            if (acknowledge_reset(session, &record) != 0) {
                portb_error("reset-ack", errno);
                free_outer_record(&record);
                return -1;
            }
        } else if (record.type == OUTER_DATA) {
            int result = handle_data_record(session, config, &record);

            if (result == AGENT_STOPPED) {
                free_outer_record(&record);
                return AGENT_STOPPED;
            }
            if (result != 0) {
                portb_error("data", errno);
                free_outer_record(&record);
                return -1;
            }
        } else {
            portb_error("outer-type", record.type);
            free_outer_record(&record);
            return -1;
        }
        free_outer_record(&record);
    }
}

/*
 * Direct mode runs as PID 1 and powers the VM off itself. In sandbox mode the
 * init agent supervises this process and unmounts the live share, overlay,
 * layers, and scratch before it powers the VM off.
 */
static int finish_agent(const struct agent_config *config, int status)
{
    char code[12];

    if (config->direct) {
        snprintf(code, sizeof(code), "%d", status);
        execl("/sbin/nvx-exit", "nvx-exit", code, (char *)NULL);
    }
    return status;
}

int main(int argc, char **argv)
{
    struct control_session session = {0};
    struct agent_config config;
    int result;

    if (argc >= 2 && strcmp(argv[1], "--exec-config-fd") == 0) {
        return launch_workload(argc, argv);
    }
    if (argc != 8) {
        return 125;
    }
    config.rootfs = argv[2];
    config.hostname = argv[3];
    config.uid = argv[4];
    config.gid = argv[5];
    config.user = argv[6];
    config.home = argv[7];
    config.direct = strcmp(config.rootfs, "-") == 0;
    session.fd = open_control_tty(argv[1]);
    if (session.fd < 0) {
        int status = errno;
        portb_error("control-open", status);
        dprintf(
            STDERR_FILENO,
            "NVX-MANAGED-ERROR: stage=control-open status=%d\n",
            status);
        return finish_agent(&config, 125);
    }
    if (configure_control_tty(session.fd) != 0) {
        int status = errno;
        portb_error("control-tty", status);
        dprintf(
            STDERR_FILENO,
            "NVX-MANAGED-ERROR: stage=control-tty status=%d\n",
            status);
        close(session.fd);
        return finish_agent(&config, 125);
    }
    result = run_agent(&session, &config);
    if (result == AGENT_STOPPED) {
        close(session.fd);
        return finish_agent(&config, 0);
    }
    if (result != 0) {
        int status = errno;
        portb_error("control-session", status);
        dprintf(
            STDERR_FILENO,
            "NVX-MANAGED-ERROR: stage=control-session status=%d\n",
            status);
        if (session.fd >= 0) {
            close(session.fd);
        }
        return finish_agent(&config, 125);
    }
    return 0;
}
