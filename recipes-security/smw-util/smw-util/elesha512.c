/*
 * This command starts failing for files >= 69632.  66048 seems safe.
 * Maybe standardize on 64K or 65536.
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <smw/names.h>
#include <smw_crypto.h>
#include <smw_osal.h>

/*
 * SMW_SUBSYSTEM_NAME_ELE
 * SMW_HASH_ALGO_NAME_SHA512
 *
 */

const char *myname;

struct smw_hash_args hash_args = {
    .version = 0,
    .subsystem_name = SMW_SUBSYSTEM_NAME_ELE,
    .algo_name = SMW_HASH_ALGO_NAME_SHA512,
};

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

/*
 * Parameter 1: Device to read
 * Parameter 2: Length of file in bytes
 */

#define SHA512_LENGTH 64
int main(int argc, const char *argv[]) {
    const char *device;
    // size_t filelength;
    char *endptr;
    uint8_t hash[SHA512_LENGTH];
    uint8_t inputhash[SHA512_LENGTH];
    uint8_t inputtext[SHA512_LENGTH * 2 + 1];
    size_t payload_length;
    uint8_t *payload;
    int input_fd;
    int sha512sum_fd;
    const char *sha512_fn;
    int i;
    int result;
    enum smw_status_code smw_result;

    // Initialize the library
    smw_result = smw_osal_lib_init();
    if (smw_result != SMW_STATUS_OK) {
        printf("SMW initialization failed with error code %d\n", smw_result);
        return 1;
    }

    myname = argv[0];
    fprintf(stderr,"%s: Enter: that is my name\n",myname);
    if(argc != 4)
        usage();

    device = argv[1] ;
    payload_length = (size_t)strtoull(argv[2], &endptr, 10);
    if(*endptr != '\0') {
        fprintf(stderr,"%s: Data length error, must be a decimal number: %s\n",myname,endptr);
        exit(2);
    }

    sha512_fn = argv[3];

    fprintf(stderr,"%s: premalloc: that is my name\n",myname);
    fprintf(stderr,"%s: allocate %u bytes\n",myname,payload_length);
    payload = malloc(payload_length);
    if(!payload) {
        fprintf(stderr,"%s: Could not allocate %lu bytes\n",myname,payload_length);
        exit(3);
    }

    hash_args.input = payload;
    hash_args.input_length = payload_length;
    hash_args.output = hash;
    hash_args.output_length = sizeof hash;

    input_fd = open(device,O_RDONLY);
    if(input_fd == -1) {
        fprintf(stderr,"%s: Could not open %s\n",myname,device);
        exit(4);
    }
    result = read(input_fd,payload,payload_length);
    if(result != payload_length){
        if (result == -1) {
            fprintf(stderr,"%s: Could not read from %s: %s\n", myname,device,strerror(errno));
            exit(5);
        }
        if (result >= 0) {
            fprintf(stderr,"%s: Read only %d bytes of %lu from %s\n",
                    myname,result,payload_length,device);
            exit(6);
        }
    }

    memset(inputtext,0,sizeof inputtext);

    sha512sum_fd = open(sha512_fn,O_RDONLY);
    if(sha512sum_fd == -1) {
        fprintf(stderr,"%s: Could not open %s\n",myname,sha512_fn);
        exit(14);
    }

    result = read(sha512sum_fd,inputtext,sizeof inputtext - 1);
    if(result != sizeof inputtext - 1){
        if (result == -1) {
            fprintf(stderr,"%s: Could not read expected hash on input: %s\n", myname,strerror(errno));
            exit(7);
        }
        if (result >= 0) {
            fprintf(stderr,"%s: Read only %d bytes of %lu\n",myname,result,sizeof inputtext - 1);
            if(result > 0) {
                inputtext[result] = 0;
                fprintf(stderr,"%s: |%s|\n",myname,inputtext);
            }
            exit(8);
        }
    }
    for (i=0;i<sizeof inputhash;i++) {
        char a[3];
        a[2] = 0;
        a[0] = inputtext[i*2];
        a[1] = inputtext[i*2 + 1];
        inputhash[i] = strtoull(a,&endptr,16);
        if(*endptr != '\0') {
            fprintf(stderr,"%s: Input hash hex string is bad (Must be 0-9, A-F and %lu characters): %s\n",
                    myname,sizeof inputtext - 1,inputtext);
            exit(9);
        }
    }
    fprintf(stderr,"Input hash is:\n");
    for (i=0;i<sizeof inputhash;i++) {
        fprintf(stderr,"%02x",inputhash[i]);
    }
    fputc('\n',stderr);

    fprintf(stderr,"%s: version: %d subsystem: %d algo_name: %d\n",
            myname,hash_args.version,hash_args.subsystem_name,hash_args.algo_name);
    fprintf(stderr,"%s: input: %02x%02x-%02x%02x length %d\n",
            myname,hash_args.input[0],hash_args.input[1],
            hash_args.input[hash_args.input_length-2],hash_args.input[hash_args.input_length-1],
            hash_args.input_length);
    sleep(5);
    fprintf(stderr,"%s: output_length: %u\n",myname,hash_args.output_length);
    if(hash_args.output_length != SHA512_LENGTH) {
        fprintf(stderr,"%s: Unexpected output hash length: %u/%u\n",
                myname,hash_args.output_length,SHA512_LENGTH);
    }
    sleep(5);
    // Compute the hash
    fputs("Computing hash next\n",stderr);
    smw_result = smw_hash(&hash_args);
    fputs("After computing hash\n",stderr);
    if (smw_result != SMW_STATUS_OK) {
            fprintf(stderr,"%s: smw_hash returns error code: %d\n",myname,(int)smw_result);
            exit(10);
    }


    // Use the hash (e.g., print it)
    for (size_t i = 0; i < SHA512_LENGTH; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");

    if (memcmp(inputhash,hash,SHA512_LENGTH) == 0)
        fprintf(stderr,"Hashes match\n");
    else {
        fprintf(stderr,"ERROR: Hashes mismatch\n");
        exit(12);
    }

    return 0;
}
