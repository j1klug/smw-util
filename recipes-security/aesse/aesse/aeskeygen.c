#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include "common/key_store.h"
#include "hsm_api.h"

#define KEYSTOREID 0x0001
#define KEYSTOREAUTHNONCE 0xddc4
#define KEYGROUP 0x7

/*
 *   #define KEYID 0xb8ae6e50u
 * hsmaes: hsmaes.c:150: Key ID (0xb8ae6e50) Already Exists.
 */
// #define KEYID 0x31110011u  // Working key id
// #define KEYID 0x6f0258ffu  // Broken key id
#define KEYID 0x2fff31f8u

const char *myname;
#define SHA512_LENGTH 64
#define BSIZE (64 * 1024)

// #define DEBUG_MODE

#ifdef DEBUG_MODE
#define DEBUG(fmt, ...) fprintf(stderr, "%s: %s:%d: " fmt "\n", myname, __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define DEBUG(fmt, ...) /* Do nothing */
#endif

#define MSG(fmt, ...) fprintf(stderr, "%s: %s:%d: " fmt "\n", myname, __FILE__, __LINE__, ##__VA_ARGS__)

int main(int argc, char *argv[]) {
    hsm_hdl_t session_hdl;
    open_session_args_t session_args = {0};
    hsm_err_t err;

    open_svc_key_store_args_t open_svc_key_store_args = {0};
    hsm_hdl_t key_store_hdl, key_mgmt_hdl;

    myname = argv[0];
    DEBUG("Enter:\n");

    DEBUG("Open session next\n");
    session_args.mu_type = HSM1;

    // Open a session
    err = hsm_open_session(&session_args, &session_hdl);
    if (err != HSM_NO_ERROR) {
        printf("Failed to open HSM session with error: 0x%x\n", err);
        exit(1);
    }
    DEBUG("Completed session open\n");

    // Create
    open_svc_key_store_args.key_store_identifier = KEYSTOREID;
    open_svc_key_store_args.authentication_nonce = KEYSTOREAUTHNONCE;

    open_svc_key_store_args.flags = HSM_SVC_KEY_STORE_FLAGS_CREATE | HSM_SVC_KEY_STORE_FLAGS_STRICT_OPERATION;

    err = hsm_open_key_store_service(session_hdl, &open_svc_key_store_args, &key_store_hdl);
    if(err==HSM_KEY_STORE_CONFLICT){
        DEBUG("create key store failed, try to load key store\n");

        err=hsm_close_session(session_hdl);
        if(err==HSM_NO_ERROR){
            DEBUG("hsm_close_session success\n");
        }else{
            MSG("hsm_close_session failed, err=0x%X\n",err);
            exit(2);
        }

        err = hsm_open_session(&session_args, &session_hdl);
        if (err != HSM_NO_ERROR) {
            MSG("Failed to open HSM session with error: 0x%x\n", err);
            exit(3);
        }
        DEBUG("Completed session open\n");

        open_svc_key_store_args.flags = 0;
        err = hsm_open_key_store_service(session_hdl, &open_svc_key_store_args, &key_store_hdl);
        if(err != HSM_NO_ERROR){
            hsm_close_key_store_service (key_store_hdl);
            hsm_close_session(session_hdl);
            MSG("hsm_open_key_store_service failed, err=0x%X\n",err);
            exit(4);
        } else {
            DEBUG("hsm_open_key_store_service success\n");
        }
    }

    // Open key management service
    open_svc_key_management_args_t key_mgmt_args;

    memset(&key_mgmt_args, 0, sizeof(key_mgmt_args));

    err = hsm_open_key_management_service(key_store_hdl, &key_mgmt_args, &key_mgmt_hdl);
    if(err != HSM_NO_ERROR){
        hsm_close_key_store_service (key_store_hdl);
        hsm_close_session(session_hdl);
        MSG("hsm_open_key_management failed, err=0x%X\n",err);
        exit(7);
    } else {
        DEBUG("hsm_open_key_management success\n");
    }


    // Generate key
    op_generate_key_args_t key_gen_args;
    uint32_t key_id = KEYID;

    DEBUG("Key prior to operation is 0x%x\n",key_id);
    memset(&key_gen_args, 0, sizeof(key_gen_args));
    key_gen_args.key_identifier = &key_id;
    key_gen_args.out_size = 0;
    key_gen_args.key_group = KEYGROUP;
    key_gen_args.flags = HSM_OP_KEY_GENERATION_FLAGS_STRICT_OPERATION;
    key_gen_args.key_lifetime = HSM_SE_KEY_STORAGE_PERSISTENT;
    key_gen_args.key_usage = HSM_KEY_USAGE_ENCRYPT | HSM_KEY_USAGE_DECRYPT;
    key_gen_args.permitted_algo = PERMITTED_ALGO_ALL_CIPHER;
    key_gen_args.bit_key_sz = HSM_KEY_SIZE_AES_256;
    key_gen_args.key_lifecycle = 0;
    key_gen_args.key_type = HSM_KEY_TYPE_AES;
    key_gen_args.out_key = NULL;

    // Generate Persistent Key
    err = hsm_generate_key(key_mgmt_hdl, &key_gen_args);    // Fails
    if (err == HSM_ID_CONFLICT) {
        MSG("WARNING: Key ID (0x%x) Already Exists.\n",KEYID);
        key_id = KEYID;
        //Because In case of failure, Key ID is set 0 at SAB layer.
    } else if(err == HSM_NO_ERROR){
        DEBUG("hsm_generate_key success\n");
    } else {
        hsm_close_key_store_service (key_store_hdl);
        hsm_close_session(session_hdl);
        MSG("hsm_generate_key failed, err=0x%X\n",err);
        exit(8);
    }
    DEBUG("Key-ID after operation is 0x%x\n",key_id);
    hsm_close_key_store_service (key_store_hdl);
    hsm_close_session(session_hdl);
    return 0;
}
