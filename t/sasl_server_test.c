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
#include "cbsasl/cbsasl.h"
#include "cram-md5/hmac.h"

const char* cbpwfile = "/tmp/sasl_server_test.pw";

static void create_pw_file() {
    FILE *fp = fopen(cbpwfile, "w");
    assert(fp != NULL);

    fprintf(fp, "mikewied mikepw \ncseo cpw \njlim jpw \n");
    assert(fclose(fp) == 0);

    putenv("ISASL_PWFILE=/tmp/sasl_server_test.pw");
}

static void remove_pw_file() {
    assert(remove(cbpwfile) == 0);
}

static void construct_cram_md5_credentials(char* buffer,
                                           unsigned* bufferlen,
                                           const char* user,
                                           unsigned userlen,
                                           const char* pass,
                                           unsigned passlen,
                                           const char* challenge,
                                           unsigned challengelen) {
    memcpy(buffer, user, userlen);
    buffer[userlen + 1] = ' ';

    unsigned char digest[DIGEST_LENGTH];
    hmac_md5((char*)challenge, challengelen, (char*)pass, passlen, digest);

    int i;
    char md5string[DIGEST_LENGTH * 2];
    for(i = 0; i < DIGEST_LENGTH; ++i) {
        sprintf(&md5string[i*2], "%02x", (unsigned int)digest[i]);
    }

    memcpy(buffer + userlen + 1, (char*)md5string, (DIGEST_LENGTH * 2));
    *bufferlen = 1 + (DIGEST_LENGTH * 2) + userlen;
}

static void test_list_mechs() {
    const char* mechs = NULL;
    unsigned len = 0;
    cbsasl_error_t err = cbsasl_list_mechs(&mechs, &len);
    assert(err == SASL_OK);
    assert(strncmp(mechs, "CRAM-MD5 PLAIN", len) == 0);
    assert(strncmp(mechs, "CRDM-MD5 PLAIN", len) != 0);
}

static void test_plain_auth() {
    cbsasl_conn_t* conn = NULL;

    cbsasl_error_t err = cbsasl_init();
    assert(err == SASL_OK);

    err = cbsasl_start(&conn, "bad_mech");
    assert(err == SASL_BADPARAM);

    err = cbsasl_start(&conn, "PLAIN");
    assert(err == SASL_CONTINUE);

    const char* output = NULL;
    unsigned outputlen = 0;
    err = cbsasl_step(conn, "mikewied\0mikepw", 15, &output, &outputlen);
    assert(err == SASL_OK);
    if (output != NULL) {
        free((char*)output);
    }

    cbsasl_dispose(&conn);
    assert(conn == NULL);
}

static void test_cram_md5_auth() {
    const char* user = "mikewied";
    const char* pass = "mikepw";
    cbsasl_conn_t* conn = NULL;

    cbsasl_error_t err = cbsasl_init();
    assert(err == SASL_OK);

    err = cbsasl_start(&conn, "CRAM-MD5");
    assert(err == SASL_CONTINUE);
    assert(conn->sasl_data_len == 30);

    char creds[128];
    unsigned credslen = 0;
    construct_cram_md5_credentials(creds, &credslen, user, strlen(user), pass,
                                   strlen(pass), conn->sasl_data,
                                   conn->sasl_data_len);

    const char* output = NULL;
    unsigned outputlen = 0;
    err = cbsasl_step(conn, creds, credslen, &output, &outputlen);
    assert(err == SASL_OK);
    if (output != NULL) {
        free((char*)output);
    }

    cbsasl_dispose(&conn);
    assert(conn == NULL);
}

int main() {
    create_pw_file();

    test_list_mechs();
    test_plain_auth();
    test_cram_md5_auth();

    remove_pw_file();
    return 0;
}
