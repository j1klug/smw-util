#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "common/key_store.h"
#include "hsm_api.h"

#define KEYSTOREID 0x0001
#define KEYSTOREAUTHNONCE 0xddc4
#define KEYGROUP 0x7

/*
 *   #define KEYID 0xb8ae6e50u
 * hsmaes: hsmaes.c:150: Key ID (0xb8ae6e50) Already Exists.
 */
#define KEYID 0x31110011u  // Example key id

static uint8_t SM2_IDENTIFIER[16] = {
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
};

const char *myname;

// #define DEBUG_MODE

#ifdef DEBUG_MODE
#define DEBUG(fmt, ...) fprintf(stderr, "%s: %s:%d: " fmt "\n", myname, __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define DEBUG(fmt, ...) /* Do nothing */
#endif

#define MSG(fmt, ...) fprintf(stderr, "%s: %s:%d: " fmt "\n", myname, __FILE__, __LINE__, ##__VA_ARGS__)
void usage(void)
{
    MSG("Usage:\n%s outfile\n",myname);
}
int main(int argc, char *argv[]) {
    hsm_hdl_t session_hdl;
    open_session_args_t session_args = {0};
    hsm_err_t err;
    char *endptr;
    int i;
    int result;
    uint8_t *sp;
    size_t blength; // Byte length of payload
    uint8_t *od;
    char *input_string;
    char convert[3];
    open_svc_key_store_args_t open_svc_key_store_args = {0};
    hsm_hdl_t key_store_hdl, key_mgmt_hdl;
    op_cipher_one_go_args_t cipher_args = {0};
    int fdin;
    const char *fnin;
    int exitstatus = 0;
    struct stat statbuf;

    myname = argv[0];
    DEBUG("Enter:\n");
    if (argc != 2) {
        usage();
        exit(1);
    }

    fnin = argv[1];
    fdin = open(fnin,O_RDONLY);
    if(fdin == -1) {
        MSG("ERROR: open: %s Failed: %s\n",fnin,strerror(errno));
        exit(7);
    }
    result = fstat(fdin,&statbuf);
    if (result == -1) {
        MSG("ERROR: stat: %s Failed: %s\n",fnin,strerror(errno));
        exitstatus = 21;
        exit(8);
    }

    blength = statbuf.st_size;
    sp = malloc(blength);


    result = read(fdin,sp,blength);
    if (result != blength) {
        if (result == -1) {
            MSG("ERROR: read: %s Failed: %s\n",fnin,strerror(errno));
            exit(9);
        }
        if(result != blength) {
            MSG("ERROR: read not complete: %d/%d\n",result,blength);
            exit(10);
        }
    }

    od = malloc(blength);

#ifdef DEBUG_MODE
    fprintf(stderr,"Input is:\n");
    for (i=0;i<blength;i++) {
        fprintf(stderr,"%02x",sp[i]);
    }
    fputc('\n',stderr);
#endif


    DEBUG("Open session next\n");
    session_args.mu_type = HSM1;

    // Open a session
    err = hsm_open_session(&session_args, &session_hdl);
    if (err != HSM_NO_ERROR) {
        printf("Failed to open HSM session with error: 0x%x\n", err);
        exit(13);
    }
    DEBUG("Completed session open\n");

    open_svc_key_store_args.key_store_identifier = KEYSTOREID;
    open_svc_key_store_args.authentication_nonce = KEYSTOREAUTHNONCE;
    open_svc_key_store_args.flags = HSM_SVC_KEY_STORE_FLAGS_LOAD;

    err = hsm_open_key_store_service(session_hdl, &open_svc_key_store_args, &key_store_hdl);
    if(err != HSM_NO_ERROR){
        hsm_close_key_store_service (key_store_hdl);
        hsm_close_session(session_hdl);
        MSG("hsm_open_key_store_service failed, err=0x%X\n",err);
        exit(14);
    } else {
        DEBUG("hsm_open_key_store_service success\n");
    }

    // Open key management service
    open_svc_key_management_args_t key_mgmt_args;

    memset(&key_mgmt_args, 0, sizeof(key_mgmt_args));

    err = hsm_open_key_management_service(key_store_hdl, &key_mgmt_args, &key_mgmt_hdl);
    if(err != HSM_NO_ERROR){
        hsm_close_key_store_service (key_store_hdl);
        hsm_close_session(session_hdl);
        MSG("hsm_open_key_management failed, err=0x%X\n",err);
        exit(17);
    } else {
        DEBUG("hsm_open_key_management success\n");
    }

    hsm_hdl_t cipher_hdl = 0;
    open_svc_cipher_args_t open_cipher_args = {0};

    err = hsm_open_cipher_service(key_store_hdl, &open_cipher_args, &cipher_hdl);
    if(err != HSM_NO_ERROR){
        hsm_close_key_store_service (key_store_hdl);
        hsm_close_session(session_hdl);
        MSG("hsm_open_cipher_service failed, err=0x%X\n",err);
        exit(18);
    } else {
        DEBUG("hsm_open_cipher_service success: cipher_hdl: 0x%llx open_cipher_args.cipher_hdl: 0x%llx\n",
              (unsigned long long)cipher_hdl,(unsigned long long)open_cipher_args.cipher_hdl);
    }


    memset(&cipher_args,0,sizeof cipher_args);
    cipher_args.key_identifier = KEYID;
    cipher_args.iv = SM2_IDENTIFIER;
    cipher_args.iv_size = sizeof(SM2_IDENTIFIER);
    cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_DECRYPT;
    cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_CBC;
    cipher_args.input = sp;
    cipher_args.input_size = blength;
    cipher_args.output = od;
    cipher_args.output_size = blength;

    // err = hsm_cipher(cipher_hdl,&cipher_args);
    err = hsm_cipher_one_go(cipher_hdl,&cipher_args);

    if(err != HSM_NO_ERROR){
        exitstatus = 19;
        MSG("hsm_do_cipher failed, err=0x%X\n",err);
        goto doexit;
    } else {
        DEBUG("hsm_do_cipher success\n");
    }


    DEBUG("Output is:\n");
    for (i=0;i<blength;i++)
        fprintf(stderr,"%02x",od[i]);
    fputc('\n',stderr);

doexit:
    hsm_close_cipher_service(cipher_hdl);
    hsm_close_key_store_service (key_store_hdl);
    hsm_close_session(session_hdl);
    return exitstatus;
}

