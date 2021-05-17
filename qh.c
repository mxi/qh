#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define ARRAY_SIZE(array, type) ((size_t)(sizeof(array) / sizeof(type)))

/* +----------------------------------------------------------------+ */
/* | Hex Conversion                                                 | */
/* +----------------------------------------------------------------+ */
static char const * const hex_digits = "0123456789abcdef";

static char
get_hex_digit32(uint32_t value, size_t place)
{
    uint32_t mask = 0xf << (place * 4);
    uint32_t digit_val = (value & mask) >> (place * 4);
    return hex_digits[(size_t)digit_val];
}

static char
get_hex_digit64(uint64_t value, size_t place)
{
    uint64_t mask = 0xfL << (place * 4);
    uint64_t digit_val = (value & mask) >> (place * 4);
    return hex_digits[(size_t)digit_val];
}

static void
to_fixed_hex32(uint32_t value, char *at_least_8_chars)
{
    char *out = at_least_8_chars;
    for (size_t i = 0; i < 8; ++i) {
        out[i] = get_hex_digit32(value, 7-i);
    }
}

static void
to_fixed_hex64(uint64_t value, char *at_least_16_chars)
{
    char *out = at_least_16_chars;
    for (size_t i = 0; i < 16; ++i) {
        out[i] = get_hex_digit64(value, 15-i);
    }
}

/* +----------------------------------------------------------------+ */
/* | String Buffer (For input reading)                              | */
/* +----------------------------------------------------------------+ */
#define BUFFER_BLOCK_SIZE 4096 

typedef struct Buffer
{
    char * base;
    char * head;
    char * end;
} Buffer;

static size_t
buffer_block_align(size_t size)
{
    size_t const BFSZ = BUFFER_BLOCK_SIZE;
    return BFSZ * ((size + BFSZ - 1) / BFSZ);
}

static size_t
buffer_get_cap(Buffer *buf)
{
    return buf->end - buf->base;
}

static size_t
buffer_get_size(Buffer *buf)
{
    return buf->head - buf->base;
}

static bool
buffer_ensure_capacity(Buffer *buf, size_t required)
{
    size_t cap = buffer_get_cap(buf);
    size_t size = buffer_get_size(buf);
    if (cap >= required) {
        return true;
    }
    size_t aligned = buffer_block_align(required);
    char *base = realloc(buf->base, sizeof(char) * aligned);
    if (!base) {
        return false;
    }
    buf->base = base;
    buf->head = base + size;
    buf->end = base + cap;
    return true;
}

static bool
buffer_ensure_fits(Buffer *buf, size_t amount)
{
    return buffer_ensure_capacity(buf, buffer_get_size(buf) + amount);
}

static bool
buffer_new(Buffer *buf)
{
    buf->base = NULL;
    buf->head = NULL;
    buf->end = NULL;
    return buffer_ensure_capacity(buf, BUFFER_BLOCK_SIZE);
}

static void
buffer_del(Buffer *buf)
{
    if (buf->base) {
        free(buf->base);
        buf->base = NULL;
        buf->head = NULL;
        buf->end = NULL;
    }
}

static bool
buffer_putc(Buffer *buf, char ch)
{
    if(!buffer_ensure_fits(buf, 1)) {
        return false;
    }
    *(buf->head++) = ch;
    return true;
}

static bool
buffer_nputs(Buffer *buf, char *chunk, size_t size)
{
    if(!buffer_ensure_fits(buf, size)) {
        return false;
    }
    strncpy(buf->head, chunk, size);
    buf->head += size;
    return true;
}

static bool
buffer_puts(Buffer *buf, char *str)
{
    size_t len = strlen(str);
    return buffer_nputs(buf, str, len);
}

/* WARNING: malloc'ed, MUST free after use */
static char *
buffer_to_string(Buffer *buf)
{
    size_t size = buffer_get_size(buf);
    char *string = calloc(size + 1, sizeof(char));
    if (!string) {
        return NULL;
    }
    strncpy(string, buf->base, size);
    string[size] = 0;
    return string;
}
   
/* +----------------------------------------------------------------+ */
/* | Algorithm Interface                                            | */
/* +----------------------------------------------------------------+ */
typedef enum HashSize
{
    H32 = 32,
    H64 = 64
} HashSize;

typedef struct Algorithm
{
    HashSize size;
    const union 
    {
        uint32_t(*func32)(char const *);
        uint64_t(*func64)(char const *);
    };
    char const *name;
    char const *author;
    char const *desc;
} Algorithm;

/* +----------------------------------------------------------------+ */
/* + Functions 32                                                   + */
/* +----------------------------------------------------------------+ */
/**
 * Basic, often terrible, cumulative sum algorithm.
 * source: http://www.cse.yorku.ca/~oz/hash.html
 */
static uint32_t
sum32(char const *message)
{
    uint32_t hash = 0;
    while (*message != 0) {
        hash += *(message++);
    }
    return hash;
}

/**
 * Well rounded, simple hash function.
 * source: http://www.cse.yorku.ca/~oz/hash.html
 */
static uint32_t
djb2(char const *message)
{
    uint32_t hash = 5381;
    int c;
    while (c = *message++) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

/**
 * Revised version of djb2, preferred by author himself.
 * source: http://www.cse.yorku.ca/~oz/hash.html
 */
static uint32_t
djb2xor(char const *message)
{
    uint32_t hash = 5381;
    int c;
    while (c = *message++) {
        hash = ((hash << 5) + hash) ^ c;
    }
    return hash;
}

/**
 * Used in the SDBM database library.
 * source: http://www.cse.yorku.ca/~oz/hash.html
 */
static uint32_t
sdbm(char const *message)
{
    uint32_t hash = 0;
    int c;
    while(c = *message++) {
        hash = c + (hash << 6) + (hash << 16) - hash;
    }
    return hash;
}

/**
 * source: http://www.burtleburtle.net/bob/hash/doobs.html
 */
static uint32_t
one_at_a_time(char const *message)
{
    uint32_t hash = 0;
    int c;
    while (c = *message++) {
        hash += c;
        hash += hash << 10;
        hash ^= hash >> 6;
    }
    hash += hash << 3;
    hash ^= hash >> 11;
    hash += hash << 15;
    return hash;
}

/* +----------------------------------------------------------------+ */
/* | Functions 64                                                   | */
/* +----------------------------------------------------------------+ */
static uint64_t
sum64(char const *message)
{
    uint64_t hash = 0;
    while (*message != 0) {
        hash += *(message++);
    }
    return hash;
}

/* +----------------------------------------------------------------+ */
/* | Algorithm Records                                              | */
/* +----------------------------------------------------------------+ */
static Algorithm algorithms[] = {
    /* 32-bit algorithms */
    { .size=H32, .func32=sum32         , .name="sum32"  , .author=""             , .desc="cumulative byte sum (lose lose)" },
    { .size=H32, .func32=djb2          , .name="djb2"   , .author="Dan Bernstein", .desc="general purpose LCG"             },
    { .size=H32, .func32=djb2xor       , .name="djb2xor", .author="Dan Bernstein", .desc=""                                },
    { .size=H32, .func32=sdbm          , .name="sdbm"   , .author=""             , .desc="part of sdbm database library"   },
    { .size=H32, .func32=one_at_a_time , .name="oaat"   , .author="Bob Jenkins"  , .desc="one at a time"                   },
    /* 64-bit algorithms */
    { .size=H64, .func64=sum64         , .name="sum64"  , .author=""             , .desc="cumulative byte sum (lose lose)" },
};

static Algorithm *
algo_lookup(char const *name)
{
    size_t len = ARRAY_SIZE(algorithms, Algorithm);
    for (size_t i = 0; i < len; ++i) {
        if (strcmp(algorithms[i].name, name) == 0) {
            return &algorithms[i];
        }
    }
    return NULL;
}

/* +----------------------------------------------------------------+ */
/* | Program                                                        | */
/* +----------------------------------------------------------------+ */
typedef enum InputMode
{
    I_ARGS,
    I_STDIN,
    I_FILE
} InputMode;

typedef struct Options
{
    bool              list_help;
    bool              list_algorithms;
    bool              no_exec;          /* true when user needs help (ex. -h, -l) */
    Algorithm const * algorithm;
    InputMode         inmode;
    char            * file;
} Options;

static void
list_help()
{
    puts(
    "qh - quick, non-cryptographic string hashing utility            \n"
    "usage: qh [-h][-l][-a name][-s][-f path] [message...]           \n"
    "                                                                \n"
    "USAGE                                                           \n"
    "  ARGUMENTS                                                     \n"
    "    $: qh -a djb2 hello world                                   \n"
    "                                                                \n"
    "    will compute the djb2 hash of 'hello world'. This is        \n"
    "    typically the desired usage.                                \n"
    "                                                                \n"
    "  STDIN                                                         \n"
    "    $: qh -a djb2 -s                                            \n"
    "    > hello world^D                                             \n"
    "                                                                \n"
    "    will compute the djb2 hash of 'hello world' where ^D is the \n"
    "    EOF token (<C-D> on UNIX).                                  \n"
    "                                                                \n"
    "  FILES                                                         \n"
    "    $: echo -n hello world > message                            \n"
    "    $: qh -a djb2 -f message                                    \n"
    "                                                                \n"
    "    will compute the djb2 hash of 'hello world' in the          \n"
    "    message file.                                               \n"
    "                                                                \n"
    "OPTIONS                                                         \n"
    "  -h                                                            \n"
    "    print this help menu.                                       \n"
    "                                                                \n"
    "  -l                                                            \n"
    "    list all hard-coded hashing algorithms and information      \n"
    "    regarding them such as the hash size, author name, and      \n"
    "    description.                                                \n"
    "                                                                \n"
    "  -a name                                                       \n"
    "    specify an algorithm to use to hash the input.              \n"
    "                                                                \n"
    "  -s                                                            \n"
    "    use stdin as input.                                         \n"
    "                                                                \n"
    "  -f path                                                       \n"
    "    use a file as input.                                        \n"
    "                                                                \n"
    "INFO                                                            \n"
    "  this is a FOSS program; MIT license.                          \n"
    "  contribute at https://github.com/mxi/qh                       \n"
    );
}

static void
list_algorithms()
{
    printf("%-20s %-6s %-20s %s\n", "ALGORITHM", "SIZE", "AUTHOR", "DESCRIPTION");
    size_t len = ARRAY_SIZE(algorithms, Algorithm);
    for (size_t i = 0; i < len; ++i) {
        Algorithm const *algo = &algorithms[i];
        printf("%-20s %-6d %-20s %s\n", 
            algo->name, 
            algo->size, 
            algo->author,
            algo->desc);
    }
}

static void
load_opts(Options *opts, int argc, char *argv[])
{
    int opt;
    while ((opt = getopt(argc, argv, "hla:sf:")) != -1) {
        switch (opt) {
            case 'h': {
                opts->list_help = true;
                opts->no_exec = true;
                break;
            }
            case 'l': {
                opts->list_algorithms = true;
                opts->no_exec = true;
                break;
            }
            case 'a': {
                Algorithm const *algo = algo_lookup(optarg);
                if (!algo) {
                    fprintf(stderr, "qh: cannot find hashing algorithm '%s'\n", optarg);
                    fprintf(stderr, "qh: use -l for all known algorithms\n");
                    opts->no_exec = true;
                }
                else {
                    opts->algorithm = algo;
                }
                break;
            }
            case 's': {
                opts->inmode = I_STDIN;
                break;
            }
            case 'f': {
                opts->inmode = I_FILE;
                if (opts->file) {
                    free(opts->file);
                }
                opts->file = calloc(strlen(optarg), sizeof(char));
                strcpy(opts->file, optarg);
                break;
            }
        }
    }
}

static char const *
get_message_from_args(int argc, char *argv[], int argv_offset)
{
    char const *message = NULL;
    Buffer buf;
    if(!buffer_new(&buf)) {
        fprintf(stderr, "failed to allocate message buffer.\n");
        goto exit;
    }
    for (int i = argv_offset; i < argc; ++i) {
        if (!buffer_puts(&buf, argv[i])) {
            fprintf(stderr, "failed to write argument %d into buffer.\n", i);
            goto exit;
        }
        if (i + 1 < argc) {
            if (!buffer_putc(&buf, ' ')) {
                fprintf(stderr, 
                    "failed to add whitespace after "
                    "argument %d into buffer.\n", i);
                goto exit;
            }
        }
    }
    message = buffer_to_string(&buf);
    if (!message) {
        fprintf(stderr, "failed to allocate message transfer string.\n");
        goto exit;
    }

    exit:
    buffer_del(&buf);
    return message;
}

static char const *
get_message_from_stream(FILE *stream)
{
    char const *message = NULL;
    Buffer buf;
    if(!buffer_new(&buf)) {
        fprintf(stderr, "failed to allocate message buffer.\n");
        goto exit;
    }

    char block[4096];
    size_t read;
    do {
        read = fread(block, sizeof(char), 4096, stream);
        if (!buffer_nputs(&buf, block, read)) {
            fprintf(stderr, "failed to write stream block into buffer.\n");
            goto exit;
        }
    }
    while (read != 0);

    message = buffer_to_string(&buf);
    if (!message) {
        fprintf(stderr, "failed to allocate message transfer string.\n");
        goto exit;
    }

    exit:
    buffer_del(&buf);
    return message;
}

static void
exec_hash(Options const *opts, int argc, char *argv[], int argv_offset) 
{
    if (!opts->algorithm) {
        fprintf(stderr, "specify an algorithm with -a\n");
        return;
    }

    char const *message;
    switch (opts->inmode) {
        case I_ARGS: {
            message = get_message_from_args(argc, argv, argv_offset);
            break;
        }
        case I_STDIN: {
            message = get_message_from_stream(stdin);
            break;
        }
        case I_FILE: {
            FILE *file = fopen(opts->file, "rb");
            if (!file) {
                fprintf(stderr, "could not open file %s\n", opts->file);
            }
            else {
                message = get_message_from_stream(file);
                fclose(file);
            }
            break;
        }
        default: {
            fprintf(stderr, "unknown input method.\n");
            break;
        }
    }

    if (message) {
        Algorithm const *algo = opts->algorithm;
        switch (algo->size) {
            case H32: {
                char hash[9];
                hash[8] = 0;
                to_fixed_hex32(algo->func32(message), hash);
                puts(hash);
                break;
            }
            case H64: {
                char hash[17];
                hash[16] = 0;
                to_fixed_hex64(algo->func64(message), hash);
                puts(hash);
                break;
            }
            default: {
                fprintf(stderr, "internal: wrong hash size %d.\n", algo->size);
                break;
            }
        }
    }
}

int
main(int argc, char *argv[])
{
    Options opts = {
        .inmode = I_ARGS
    };

    /* configure options */
    load_opts(&opts, argc, argv);

    /* execute on options */
    if (opts.list_help) {
        list_help();
    }

    if (opts.list_algorithms) {
        list_algorithms();
    }

    /* user wants to execute a hash */
    if (!opts.no_exec) {
        exec_hash(&opts, argc, argv, optind);
    }

    /* cleanup */
    if (opts.file) {
        free(opts.file);
    }
    return 0;
}