#include <stdio.h>
#include <string.h>
#include <smw_crypto.h>
#include <smw_osal.h>

// Function to print the hash in hexadecimal format
void print_hex(const unsigned char *hash, size_t length) {
    for (size_t i = 0; i < length; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

int main() {
    const char *message = "Hello, World!";
    unsigned char hash[64]; // SHA-512 produces a 512-bit (64-byte) hash
    unsigned int hash_len = sizeof(hash);

    // Initialize the library
    enum smw_status_code init_status = smw_osal_lib_init();
    if (init_status != SMW_STATUS_OK) {
        printf("SMW initialization failed with error code %d\n", init_status);
        return 1;
    }

    // Set up hashing parameters and compute the hash
    struct smw_hash_args args;
    memset(&args, 0, sizeof(args));
    args.version = 0;
    args.algo_name = SMW_HASH_ALGO_NAME_SHA512;
    args.input = (unsigned char *)message;
    args.input_length = strlen(message);
    args.output = hash;
    args.output_length = hash_len;

    enum smw_status_code ret = smw_hash(&args);
    if (ret != SMW_STATUS_OK) {
        printf("Hashing failed with error code %d\n", ret);
        return 1;
    }

    // Print the resulting hash
    printf("SHA-512 hash of \"%s\":\n", message);
    print_hex(hash, hash_len);

    return 0;
}
