#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include "hsm_api.h"

const char *myname;
#define SHA512_LENGTH 64
#define BSIZE (64 * 1024)

// #define DEBUG_MODE

#ifdef DEBUG_MODE
#define DEBUG(fmt, ...) fprintf(stderr, "%s: %s:%d: " fmt "\n", myname, __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define DEBUG(fmt, ...) /* Do nothing */
#endif

void
usage(void)
{
    fprintf(stderr,"%s Device Length hash\n",myname);
    fputs("   Device: Device or file\n",stderr);
    fputs("   Length: Length of data in bytes\n",stderr);
    fputs("   Text file with SHA-2 512 Sum in ASCII Hex\n",stderr);
    fputs("Expected hash is read from stdin\n",stderr);
    exit(1);
}

int do_hash_test(hsm_hdl_t session_hdl, uint8_t *hash, uint8_t *map, unsigned long long length)
{
    op_hash_one_go_args_t hash_args = {0};
    uint8_t input_data[] = "Hello, NXP Secure Enclave!";
    uint8_t output_hash[SHA512_LENGTH];  // SHA-512 output size
    hsm_err_t err;
    uint8_t *ctx_input = NULL;
    uint8_t *blockp = map;
    int result;
    int datasize;
    unsigned long long total = 0;

    hash_args.algo = HSM_HASH_ALGO_SHA_512;
    hash_args.svc_flags = HSM_HASH_FLAG_GET_CONTEXT;
    DEBUG("About to call hsm_do_hash get context\n");
    err = hsm_do_hash(session_hdl, &hash_args);
    DEBUG("hsm_do_hash get context result: 0x%x\n", err);
    ctx_input = (uint8_t *)malloc(hash_args.context_size);
    if (!ctx_input) {
        fprintf(stderr,
            "%s: Error: failed to allocate memory for HASH ctx.\n",
            myname);
        exit(11);
    }
    memset(ctx_input, 0, hash_args.context_size);
    hash_args.ctx = ctx_input;
    hash_args.ctx_size = hash_args.context_size;

    if(BSIZE < length)
        datasize = BSIZE;
    else
        datasize = length;

     // Prepare the hash arguments
    hash_args.algo = HSM_HASH_ALGO_SHA_512;  // Use SHA-512 for this example
    hash_args.svc_flags = HSM_HASH_FLAG_INIT;
    hash_args.input = map;
    hash_args.input_size = datasize;  // Exclude the null terminator

    DEBUG("mmap: 0x%llx:0x%x Offset=0x%x First: 0x%02x%02x%02x%02x\n",
        (unsigned long long)hash_args.input,hash_args.input_size,(unsigned int)(hash_args.input - map),
        hash_args.input[0],hash_args.input[1],hash_args.input[2],hash_args.input[3]
    );

    // Perform the hashing operation
    DEBUG("About to call hsm_do_hash init\n");
    err = hsm_do_hash(session_hdl, &hash_args);
    if (err != HSM_NO_ERROR) {
        printf("Hashing operation failed with error: 0x%x\n", err);
        return err;
    }

    total += datasize;
    length -= datasize;
    hash_args.input_size = BSIZE;
    hash_args.svc_flags = HSM_HASH_FLAG_UPDATE;
    while(length > BSIZE) {
        hash_args.input += BSIZE;

#ifdef DEBUG_MODE
        if((total < 3*BSIZE) || (length < (3*BSIZE))) {
            DEBUG("About to call hsm_do_hash update. total=%llu count=%u\n",total,hash_args.input_size);
            DEBUG("mmap: 0x%llx:0x%x Offset=0x%x First: 0x%02x%02x%02x%02x\n",
                (unsigned long long)hash_args.input,hash_args.input_size,(unsigned int)(hash_args.input - map),
                hash_args.input[0],hash_args.input[1],hash_args.input[2],hash_args.input[3]
            );
         }
#endif
        err = hsm_do_hash(session_hdl, &hash_args);
        if (err != HSM_NO_ERROR) {
            printf("Hashing operation failed with error: 0x%x\n", err);
            return err;
        }
        total += datasize;
        length -= datasize;
    }

    hash_args.input_size = length;
    hash_args.input += BSIZE;
    hash_args.svc_flags = HSM_HASH_FLAG_FINAL;
    hash_args.output = output_hash;
    hash_args.output_size = SHA512_LENGTH;

    DEBUG("About to call hsm_do_hash final: total=0x%llx\n",total);
    DEBUG("mmap: 0x%llx:0x%x Offset=0x%x First: 0x%02x%02x%02x%02x  0x%02x%02x%02x%02x%02x%02x%02x%02x\n",
        (unsigned long long)hash_args.input,hash_args.input_size,(unsigned int)(hash_args.input - map),
        hash_args.input[0],hash_args.input[1],hash_args.input[2],hash_args.input[3],
        hash_args.input[hash_args.input_size-8],hash_args.input[hash_args.input_size-7],hash_args.input[hash_args.input_size-6],hash_args.input[hash_args.input_size-5],
        hash_args.input[hash_args.input_size-4],hash_args.input[hash_args.input_size-3],hash_args.input[hash_args.input_size-2],hash_args.input[hash_args.input_size-1],
        total
    );
    DEBUG("Last: 0x%llx for %d\n",(unsigned long long)(hash_args.input),hash_args.input_size);

    err = hsm_do_hash(session_hdl, &hash_args);
    if (err != HSM_NO_ERROR) {
        printf("Hashing operation failed with error: 0x%x\n", err);
        return err;
    }

    // Print the resulting hash
    DEBUG("SHA-512 Hash: ");
#ifdef DEBUG_MODE
    for (int i = 0; i < hash_args.output_size; i++) {
        printf("%02x", output_hash[i]);
    }
    printf("\n");
#endif

    if (memcmp(hash,output_hash,SHA512_LENGTH))  // Mismatch
        return HSM_SIGNATURE_INVALID;

    return HSM_NO_ERROR;
}

int main(int argc, char *argv[]) {
    hsm_hdl_t session_hdl;
    open_session_args_t session_args = {0};
    hsm_err_t err;
    const char *sha512sum_fn;
    int sha512sum_fd;
    size_t payload_length;
    uint8_t *payload;
    const char *device;
    uint8_t expectedhash[SHA512_LENGTH];
    uint8_t expectedhashtext[SHA512_LENGTH * 2 + 1];
    char *endptr;
    int i;
    int input_fd;
    int result;

    myname = argv[0];
    DEBUG("Enter:\n");
    if(argc != 4)
        usage();
    device = argv[1] ;
    payload_length = (size_t)strtoull(argv[2], &endptr, 10);
    if(*endptr != '\0') {
        fprintf(stderr,"%s: Data length error, must be a decimal number: %s\n",myname,endptr);
        exit(2);
    }

    sha512sum_fn = argv[3];

    memset(expectedhashtext,0,sizeof expectedhashtext);

    sha512sum_fd = open(sha512sum_fn,O_RDONLY);
    if(sha512sum_fd == -1) {
        fprintf(stderr,"%s: Could not open %s\n",myname,sha512sum_fn);
        exit(14);
    }

    result = read(sha512sum_fd,expectedhashtext,sizeof expectedhashtext - 1);
    if(result != sizeof expectedhashtext - 1){
        if (result == -1) {
            fprintf(stderr,"%s: Could not read expected hash on input: %s\n", myname,strerror(errno));
            exit(7);
        }
        if (result >= 0) {
            fprintf(stderr,"%s: Read only %d bytes of %lu\n",myname,result,sizeof expectedhashtext - 1);
            if(result > 0) {
                expectedhashtext[result] = 0;
                fprintf(stderr,"%s: |%s|\n",myname,expectedhashtext);
            }
            exit(8);
        }
    }
    for (i=0;i<sizeof expectedhash;i++) {
        char a[3];
        a[2] = 0;
        a[0] = expectedhashtext[i*2];
        a[1] = expectedhashtext[i*2 + 1];
        expectedhash[i] = strtoull(a,&endptr,16);
        if(*endptr != '\0') {
            fprintf(stderr,"%s: Input hash hex string is bad (Must be 0-9, A-F and %lu characters): %s\n",
                    myname,sizeof expectedhashtext - 1,expectedhashtext);
            exit(9);
        }
    }

#ifdef DEBUG_MODE
    fprintf(stderr,"Input hash is:\n");
    for (i=0;i<sizeof expectedhash;i++) {
        fprintf(stderr,"%02x",expectedhash[i]);
    }
    fputc('\n',stderr);
#endif

    input_fd = open(device,O_RDONLY);
    if(input_fd == -1) {
        fprintf(stderr,"%s: Could not open %s\n",myname,device);
        exit(4);
    }

    uint8_t *map = mmap(NULL, payload_length, PROT_READ, MAP_SHARED, input_fd, 0);
    if (map == MAP_FAILED) {
        fprintf(stderr,"%s: mmap fails on %s: %s\n",myname,device,strerror(errno));
        close(input_fd);
        return 1;
    }

    DEBUG("mmap: 0x%llx First: 0x%02x%02x%02x%02x 0x%02x%02x%02x%02x%02x%02x%02x%02x\n",
    (unsigned long long)map,map[0],map[1],map[2],map[3],
          map[payload_length-8],map[payload_length-7],map[payload_length-6],map[payload_length-5],
          map[payload_length-4],map[payload_length-3],map[payload_length-2],map[payload_length-1]
          );
    DEBUG("mmap: map end: 0x%llx %d\n",(unsigned long long)(map+payload_length-14680),14680);
    DEBUG("Open session next\n");
    session_args.mu_type = HSM1;

    // Open a session
    err = hsm_open_session(&session_args, &session_hdl);
    if (err != HSM_NO_ERROR) {
        printf("Failed to open HSM session with error: 0x%x\n", err);
        return -1;
    }
    DEBUG("Completed session open\n");

    // Perform hash test
    err = do_hash_test(session_hdl,expectedhash,map,payload_length);
    if (err != HSM_NO_ERROR) {
        fprintf(stderr,"%s: Hash test failed with error: 0x%x\n",myname,err);
    } else
        printf("%s: Hash passes\n",myname);

    // Close the session
    err = hsm_close_session(session_hdl);
    if (err != HSM_NO_ERROR) {
        fprintf(stderr,"Failed to close HSM session with error: 0x%x\n", err);
    }

    return 0;
}
