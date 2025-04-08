/*
JAK: Open session next
JAK: Completed session open
JAK: About to hash.  input_size=26, output_size=64

SAB Error: SAB CMD [0xcc] Resp [0x429] - MU sanity check failed / Invalid parameters.

Hashing operation failed with error: 0x4
Hash test failed with error: 0x4
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "hsm_api.h"

int do_hash_test(hsm_hdl_t session_hdl) {
    op_hash_one_go_args_t hash_args;
    uint8_t input_data[] = "Hello, NXP Secure Enclave!";
    uint8_t output_hash[64];  // SHA-256 output size
    hsm_err_t err;

    // Prepare the hash arguments
    memset(&hash_args, 0, sizeof(hash_args));
    hash_args.algo = HSM_HASH_ALGO_SHA_512;  // Use SHA-256 for this example
    hash_args.svc_flags = HSM_HASH_FLAG_ONE_SHOT;
    hash_args.input = input_data;
    hash_args.input_size = sizeof(input_data) - 1;  // Exclude the null terminator
    hash_args.output = output_hash;
    hash_args.output_size = sizeof(output_hash);
    fprintf(stderr,"JAK: About to hash.  input_size=%u, output_size=%u\n",
            hash_args.input_size,hash_args.output_size);
    // Perform the hashing operation
    err = hsm_do_hash(session_hdl, &hash_args);
    if (err != HSM_NO_ERROR) {
        printf("Hashing operation failed with error: 0x%x\n", err);
        return err;
    }

    // Print the resulting hash
    printf("SHA-512 Hash: ");
    for (int i = 0; i < hash_args.output_size; i++) {  // SHA-256 produces a 32-byte hash
        printf("%02x", output_hash[i]);
    }
    printf("\n");

    return HSM_NO_ERROR;
}

int main(int argc, char *argv[]) {
    hsm_hdl_t session_hdl;
    open_session_args_t session_args = {0};
    hsm_err_t err;

    fprintf(stderr,"JAK: Open session next\n");
    session_args.mu_type = HSM1;
    // Open a session
    err = hsm_open_session(&session_args, &session_hdl);
    if (err != HSM_NO_ERROR) {
        printf("Failed to open HSM session with error: 0x%x\n", err);
        return -1;
    }
    fprintf(stderr,"JAK: Completed session open\n");

    // Perform hash test
    err = do_hash_test(session_hdl);
    if (err != HSM_NO_ERROR) {
        printf("Hash test failed with error: 0x%x\n", err);
    }

    // Close the session
    err = hsm_close_session(session_hdl);
    if (err != HSM_NO_ERROR) {
        printf("Failed to close HSM session with error: 0x%x\n", err);
    }

    return 0;
}
