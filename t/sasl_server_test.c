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
#include "pwfile.h"
#include "util.h"

const char *cbpwfile = "sasl_server_test.pw";

static void create_pw_file()
{
    FILE *fp = fopen(cbpwfile, "w");
    assert(fp != NULL);

    fprintf(fp, "mikewied mikepw \ncseo cpw \njlim jpw \nnopass\n");
    assert(fclose(fp) == 0);

    putenv("ISASL_PWFILE=sasl_server_test.pw");
}

static void remove_pw_file()
{
    assert(remove(cbpwfile) == 0);
    free_user_ht();
}

static void construct_cram_md5_credentials(char *buffer,
                                           unsigned *bufferlen,
                                           const char *user,
                                           unsigned userlen,
                                           const char *pass,
                                           unsigned passlen,
                                           const char *challenge,
                                           unsigned challengelen)
{
    unsigned char digest[DIGEST_LENGTH];
    memcpy(buffer, user, userlen);
    buffer[userlen + 1] = ' ';

    hmac_md5((unsigned char *)challenge, challengelen, (unsigned char *)pass, passlen, digest);

    cbsasl_hex_encode(buffer + userlen + 1, (char *) digest, DIGEST_LENGTH);
    *bufferlen = 1 + (DIGEST_LENGTH * 2) + userlen;
}

static void test_list_mechs()
{
    const char *mechs = NULL;
    unsigned len = 0;
    cbsasl_error_t err = cbsasl_list_mechs(&mechs, &len);
    assert(err == SASL_OK);
    assert(strncmp(mechs, "CRAM-MD5 PLAIN", len) == 0);
    assert(strncmp(mechs, "CRDM-MD5 PLAIN", len) != 0);
}

static void test_plain_auth()
{
    cbsasl_conn_t *conn = NULL;
    const char *output = NULL;
    unsigned outputlen = 0;
    cbsasl_error_t err;

    err = cbsasl_init();
    assert(err == SASL_OK);

    err = cbsasl_server_start(&conn, "bad_mech");
    assert(err == SASL_BADPARAM);
    free((void *)output);

    /* Normal behavior */
    output = NULL;
    err = cbsasl_server_start(&conn, "PLAIN");
    assert(err == SASL_CONTINUE);

    err = cbsasl_server_step(conn, "\0mikewied\0mikepw", 16, &output, &outputlen);
    assert(err == SASL_OK);
    free((void *)output);

    /* With wrong password */
    output = NULL;
    err = cbsasl_init();
    assert(err == SASL_OK);

    err = cbsasl_server_start(&conn, "PLAIN");
    assert(err == SASL_CONTINUE);

    err = cbsasl_server_step(conn, "\0mikewied\0badpPW", 16, &output, &outputlen);
    assert(err == SASL_FAIL);
    free((void *)output);

    cbsasl_dispose(&conn);
    assert(conn == NULL);

    /* with no password */
    output = NULL;
    err = cbsasl_init();
    assert(err == SASL_OK);

    err = cbsasl_server_start(&conn, "PLAIN");
    assert(err == SASL_CONTINUE);

    err = cbsasl_server_step(conn, "\0nopass\0", 8, &output, &outputlen);
    assert(err == SASL_OK);
    free((void *)output);

    /* with authzid */
    output = NULL;
    err = cbsasl_init();
    assert(err == SASL_OK);

    err = cbsasl_server_start(&conn, "PLAIN");
    assert(err == SASL_CONTINUE);

    err = cbsasl_server_step(conn, "funzid\0mikewied\0mikepw", 22, &output, &outputlen);
    assert(err == SASL_OK);
    free((void *)output);

    /* with no pw or username ending null */
    output = NULL;
    err = cbsasl_init();
    assert(err == SASL_OK);

    err = cbsasl_server_start(&conn, "PLAIN");
    assert(err == SASL_CONTINUE);

    err = cbsasl_server_step(conn, "funzid\0mikewied", 15, &output, &outputlen);
    assert(err != SASL_OK);
    free((void *)output);

    /* with no nulls at all */
    output = NULL;
    err = cbsasl_init();
    assert(err == SASL_OK);

    err = cbsasl_server_start(&conn, "PLAIN");
    assert(err == SASL_CONTINUE);

    err = cbsasl_server_step(conn, "funzidmikewied", 14, &output, &outputlen);
    assert(err != SASL_OK);
    free((void *)output);

    cbsasl_dispose(&conn);
    assert(conn == NULL);
}

static void test_cram_md5_auth()
{
    const char *user = "mikewied";
    const char *pass = "mikepw";
    cbsasl_conn_t *conn = NULL;
    char creds[128];
    unsigned credslen = 0;
    const char *output = NULL;
    unsigned outputlen = 0;

    cbsasl_error_t err = cbsasl_init();
    assert(err == SASL_OK);

    err = cbsasl_server_start(&conn, "CRAM-MD5");
    assert(err == SASL_CONTINUE);
    assert(conn->sasl_data_len == 30);

    construct_cram_md5_credentials(creds, &credslen, user, strlen(user), pass,
                                   strlen(pass), conn->sasl_data,
                                   conn->sasl_data_len);

    err = cbsasl_server_step(conn, creds, credslen, &output, &outputlen);
    assert(err == SASL_OK);
    if (output != NULL) {
        free((char *)output);
    }

    cbsasl_dispose(&conn);
    assert(conn == NULL);
}

int main()
{
    create_pw_file();

    test_list_mechs();
    test_plain_auth();
    test_cram_md5_auth();

    remove_pw_file();
    return 0;
}
