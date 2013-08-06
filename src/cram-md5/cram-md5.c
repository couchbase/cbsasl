/*
 *     Copyright 2013 Couchbase, Inc.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#include "config.h"
#include "cram-md5.h"
#include "hmac.h"
#include "pwfile.h"

#define CHALLENGE_TEMPLATE "<xxxxxxxxxxxxxxxx.0@127.0.0.1>"
#define CHALLENGE_LENGTH strlen(CHALLENGE_TEMPLATE)
#define NONCE_LENGTH 16
#define NONCE_SWAPS 100

static void generate_nonce(char* nonce) {
    for (int i = 0; i < NONCE_LENGTH; i++) {
        nonce[i] = '0' + (rand() % 10);
    }
}

static void challenge(char** challenge, unsigned* challengelen) {
    char nonce[NONCE_LENGTH];
    generate_nonce(nonce);
    *challenge = (char*)malloc(CHALLENGE_LENGTH * sizeof(char));
    memcpy((void*)((*challenge)), CHALLENGE_TEMPLATE, CHALLENGE_LENGTH);
    memcpy((void*)((*challenge) + 1), nonce, NONCE_LENGTH);
    *challengelen = CHALLENGE_LENGTH;
}

static void print_md5(unsigned char* digest) {
    int i;
    char md5string[33];
    printf("digest: ", digest);
    for(i = 0; i < 16; ++i) {
        sprintf(&md5string[i*2], "%02x", (unsigned int)digest[i]);
    }
    printf("%s\n", md5string);
}

cbsasl_error_t cram_md5_server_init() {
    return SASL_OK;
}

cbsasl_error_t cram_md5_server_start(cbsasl_conn_t* conn) {
    challenge(&(conn->sasl_data), &(conn->sasl_data_len));
    return SASL_CONTINUE;
}

cbsasl_error_t cram_md5_server_step(cbsasl_conn_t *conn,
                                    const char* input,
                                    unsigned inputlen,
                                    const char** output,
                                    unsigned* outputlen) {
    if (inputlen <= 33) {
        return SASL_BADPARAM;
    }

    unsigned userlen = inputlen - (DIGEST_LENGTH * 2) - 1;
    char* user = (char*)malloc((userlen + 1) * sizeof(char));
    memcpy(user, input, userlen);
    user[userlen] = '\0';

    char* cfg;
    char* pass = find_pw(user, &cfg);
    if (pass == NULL) {
        return SASL_FAIL;
    }

    unsigned char digest[DIGEST_LENGTH];
    hmac_md5(conn->sasl_data, conn->sasl_data_len, pass, strlen(pass), digest);

    int i;
    char md5string[DIGEST_LENGTH * 2];
    for(i = 0; i < DIGEST_LENGTH; ++i) {
        sprintf(&md5string[i*2], "%02x", (unsigned int)digest[i]);
    }

    if (memcmp(md5string, &(input[userlen + 1]), (DIGEST_LENGTH * 2)) != 0) {
        return SASL_FAIL;
    }

    conn->config = cfg;
    *output = NULL;
    *outputlen = 0;
    return SASL_OK;
}

cbsasl_mechs_t get_cram_md5_mechs(void) {
    static cbsasl_mechs_t mechs = {
        MECH_NAME_CRAM_MD5,
        cram_md5_server_init,
        cram_md5_server_start,
        cram_md5_server_step
    };
    return mechs;
}