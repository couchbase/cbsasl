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

#include "internal.h"
#include "cbsasl/cbsasl.h"
#include "cram-md5/hmac.h"

static void create_pwdb(void) {
    assert(cbsasl_update_cred("mikewied", "mikepw", NULL) == SASL_OK);
    assert(cbsasl_update_cred("cseo", "cpw", NULL) == SASL_OK);
    assert(cbsasl_update_cred("jlim", "jpw", NULL) == SASL_OK);
}

static void remove_pwdb(void) {
    cbsasl_destroy_creds();
}

static void construct_cram_md5_credentials(char* buffer,
                                           unsigned* bufferlen,
                                           const char* user,
                                           unsigned userlen,
                                           const char* pass,
                                           unsigned passlen,
                                           const char* challenge,
                                           unsigned challengelen) {
    int i;
    char md5string[(DIGEST_LENGTH * 2) + 1]; /* sprintf adds an exta \0 */
    unsigned char digest[DIGEST_LENGTH];
    memcpy(buffer, user, userlen);
    buffer[userlen + 1] = ' ';

    hmac_md5((unsigned char*)challenge, challengelen, (unsigned char*)pass, passlen, digest);

    for(i = 0; i < DIGEST_LENGTH; ++i) {
        sprintf(&md5string[i*2], "%02x", (unsigned int)digest[i]);
    }

    memcpy(buffer + userlen + 1, (char*)md5string, (DIGEST_LENGTH * 2));
    *bufferlen = 1 + (DIGEST_LENGTH * 2) + userlen;
}

static void test_list_mechs(void) {
    const char* mechs = NULL;
    unsigned len = 0;
    cbsasl_error_t err = cbsasl_list_mechs(&mechs, &len);
    assert(err == SASL_OK);
    assert(strncmp(mechs, "CRAM-MD5 PLAIN", len) == 0);
    assert(strncmp(mechs, "CRDM-MD5 PLAIN", len) != 0);
}

static void test_plain_auth(void) {
    cbsasl_conn_t* conn = NULL;
    const char* output = NULL;
    unsigned outputlen = 0;

    cbsasl_error_t err = cbsasl_init();
    assert(err == SASL_OK);

    err = cbsasl_start(&conn, "bad_mech");
    assert(err == SASL_BADPARAM);

    err = cbsasl_start(&conn, "PLAIN");
    assert(err == SASL_CONTINUE);

    err = cbsasl_step(conn, "\0mikewied\0mikepw", 16, &output, &outputlen);
    assert(err == SASL_OK);
    if (output != NULL) {
        free((char*)output);
    }

    cbsasl_dispose(&conn);
    assert(conn == NULL);
}

static void test_cram_md5_auth(void) {
    const char* user = "mikewied";
    const char* pass = "mikepw";
    cbsasl_conn_t* conn = NULL;
    char creds[128];
    unsigned credslen = 0;
    const char* output = NULL;
    unsigned outputlen = 0;

    cbsasl_error_t err = cbsasl_init();
    assert(err == SASL_OK);

    err = cbsasl_start(&conn, "CRAM-MD5");
    assert(err == SASL_CONTINUE);
    assert(conn->sasl_data_len == 30);

    construct_cram_md5_credentials(creds, &credslen, user, strlen(user), pass,
                                   strlen(pass), conn->sasl_data,
                                   conn->sasl_data_len);

    err = cbsasl_step(conn, creds, credslen, &output, &outputlen);
    assert(err == SASL_OK);
    if (output != NULL) {
        free((char*)output);
    }

    cbsasl_dispose(&conn);
    assert(conn == NULL);
}

int main(void) {
    create_pwdb();

    test_list_mechs();
    test_plain_auth();
    test_cram_md5_auth();

    remove_pwdb();
    return 0;
}
