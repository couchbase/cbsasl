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
#include "cram-md5/cram-md5.h"
#include "cram-md5/hmac.h"
#include "plain/plain.h"
#include "pwfile.h"
#include "util.h"
#include <time.h>

#define IS_MECH(str, mech) (strncmp(str, mech, strlen(mech)))

cbsasl_error_t cbsasl_list_mechs(const char **mechs,
                                 unsigned *mechslen)
{
    *mechs = "CRAM-MD5 PLAIN";
    *mechslen = strlen(*mechs);
    return SASL_OK;
}

CBSASL_PUBLIC_API
cbsasl_error_t cbsasl_server_init()
{
    srand((unsigned int)time(NULL));
    pwfile_init();
    return load_user_db();
}

CBSASL_PUBLIC_API
cbsasl_error_t cbsasl_server_start(cbsasl_conn_t **conn,
                                   const char *mech,
                                   const char *clientin,
                                   unsigned int clientinlen,
                                   unsigned char **serverout,
                                   unsigned int *serveroutlen)
{
    cbsasl_error_t err;

    if (*conn != NULL) {
        cbsasl_dispose(conn);
    }

    *conn = calloc(1, sizeof(cbsasl_conn_t));
    if (*conn == NULL) {
        return SASL_NOMEM;
    }

    if (IS_MECH(mech, MECH_NAME_PLAIN) == 0) {
        cbsasl_mechs_t plain_mech = get_plain_mechs();
        memcpy(&(*conn)->c.server.mech, &plain_mech, sizeof(cbsasl_mechs_t));
    } else if (IS_MECH(mech, MECH_NAME_CRAM_MD5) == 0) {
        cbsasl_mechs_t cram_md5_mech = get_cram_md5_mechs();
        memcpy(&(*conn)->c.server.mech, &cram_md5_mech, sizeof(cbsasl_mechs_t));
    } else {
        cbsasl_dispose(conn);
        return SASL_BADPARAM;
    }

    if ((err = (*conn)->c.server.mech.init()) != SASL_OK) {
        cbsasl_dispose(conn);
        return err;
    }

    err = (*conn)->c.server.mech.start(*conn);
    if (serverout) {
        *serverout = (void*)(*conn)->c.server.sasl_data;
    }
    if (serveroutlen) {
        *serveroutlen = (*conn)->c.server.sasl_data_len;
    }

    if (err == SASL_CONTINUE && clientinlen != 0) {
        return cbsasl_server_step(*conn, clientin, clientinlen,
                                  (const char**)serverout, serveroutlen);
    }

    return err;
}

CBSASL_PUBLIC_API
cbsasl_error_t cbsasl_server_step(cbsasl_conn_t *conn,
                                  const char *input,
                                  unsigned inputlen,
                                  const char **output,
                                  unsigned *outputlen)
{
    if (conn->client) {
        return SASL_BADPARAM;
    }
    return conn->c.server.mech.step(conn, input, inputlen, output, outputlen);
}

CBSASL_PUBLIC_API
void cbsasl_dispose(cbsasl_conn_t **conn)
{
    if (*conn != NULL) {
        if ((*conn)->client) {
            free((*conn)->c.client.userdata);
        } else {
            free((*conn)->c.server.username);
            free((*conn)->c.server.config);
            free((*conn)->c.server.sasl_data);
        }

        free(*conn);
        *conn = NULL;
    }
}

int cbsasl_secure_compare(const char *a, const char *b, size_t len)
{
    size_t i;
    int acc = 0;
    for (i = 0; i < len; i++) {
        acc |= a[i] ^ b[i];
    }
    return acc;
}

static const char *hexchar = "0123456789abcdef";
void cbsasl_hex_encode(char *dest, const char *src, size_t srclen)
{
    size_t i;
    for (i = 0; i < srclen; i++) {
        dest[i * 2] = hexchar[(src[i] >> 4) & 0xF];
        dest[i * 2 + 1] = hexchar[src[i] & 0xF];
    }
}

CBSASL_PUBLIC_API
cbsasl_error_t cbsasl_server_refresh(void)
{
    return load_user_db();
}

CBSASL_PUBLIC_API
cbsasl_error_t cbsasl_getprop(cbsasl_conn_t *conn,
                              cbsasl_prop_t propnum,
                              const void **pvalue)
{
    if (conn->client || pvalue == NULL) {
        return SASL_BADPARAM;
    }

    switch (propnum) {
    case CBSASL_USERNAME:
        *pvalue = conn->c.server.username;
        break;
    case CBSASL_CONFIG:
        *pvalue = conn->c.server.config;
        break;
    default:
        return SASL_BADPARAM;
    }

    return SASL_OK;
}

CBSASL_PUBLIC_API
cbsasl_error_t cbsasl_setprop(cbsasl_conn_t *conn,
                              cbsasl_prop_t propnum,
                              const void *pvalue)
{
    void *old;
    if (conn->client) {
        return SASL_BADPARAM;
    }

    switch (propnum) {
    case CBSASL_USERNAME:
        old = conn->c.server.username;
        if ((conn->c.server.username = strdup(pvalue)) == NULL) {
            conn->c.server.username = old;
            return SASL_NOMEM;
        }
        break;
    case CBSASL_CONFIG:
        old = conn->c.server.config;
        if ((conn->c.server.config = strdup(pvalue)) == NULL) {
            conn->c.server.config = old;
            return SASL_NOMEM;
        }
        break;
    default:
        return SASL_BADPARAM;
    }

    free(old);
    return SASL_OK;

}


/************************************************************************
 *                       Client interface                               *
 ***********************************************************************/
CBSASL_PUBLIC_API
cbsasl_error_t cbsasl_client_new(const char *service,
                                 const char *serverFQDN,
                                 const char *iplocalport,
                                 const char *ipremoteport,
                                 const cbsasl_callback_t *prompt_supp,
                                 unsigned flags,
                                 cbsasl_conn_t **pconn)
{
    cbsasl_conn_t *conn;
    cbsasl_callback_t *callbacks = (cbsasl_callback_t*)prompt_supp;
    int ii;

    if (prompt_supp == NULL) {
        return SASL_BADPARAM;
    }

    conn = calloc(1, sizeof(*conn));
    if (conn == NULL) {
        return SASL_NOMEM;
    }

    conn->client = 1;

    ii = 0;
    /* Locate the callbacks */
    while (callbacks[ii].id != CBSASL_CB_LIST_END) {
        if (callbacks[ii].id == CBSASL_CB_USER || callbacks[ii].id == CBSASL_CB_AUTHNAME) {
            union {
                int (*get)(void *, int, const char **, unsigned int *);
                int (*proc)(void);
            } hack;
            hack.proc = callbacks[ii].proc;
            conn->c.client.get_username = hack.get;
            conn->c.client.get_username_ctx = callbacks[ii].context;
        } else if (callbacks[ii].id == CBSASL_CB_PASS) {
            union {
                int (*get)(cbsasl_conn_t *, void *, int, cbsasl_secret_t **);
                int (*proc)(void);
            } hack;
            hack.proc = callbacks[ii].proc;
            conn->c.client.get_password = hack.get;
            conn->c.client.get_password_ctx = callbacks[ii].context;
        }
        ++ii;
    }

    if (conn->c.client.get_username == NULL || conn->c.client.get_password == NULL) {
        cbsasl_dispose(&conn);
        return SASL_NOUSER;
    }

    *pconn = conn;

    (void)service;
    (void)serverFQDN;
    (void)iplocalport;
    (void)ipremoteport;
    (void)flags;

    return SASL_OK;
}

CBSASL_PUBLIC_API
cbsasl_error_t cbsasl_client_start(cbsasl_conn_t *conn,
                                   const char *mechlist,
                                   void **prompt_need,
                                   const char **clientout,
                                   unsigned int *clientoutlen,
                                   const char **mech)
{
    if (conn->client == 0) {
        return SASL_BADPARAM;
    }

    if (strstr(mechlist, "CRAM-MD5") == NULL) {
        if (strstr(mechlist, "PLAIN") == NULL) {
            return SASL_NOMECH;
        }

        *mech = "PLAIN";
        conn->c.client.plain = 1;
    } else {
        *mech = "CRAM-MD5";
        conn->c.client.plain = 0;
    }


    if (conn->c.client.plain) {
        const char *usernm = NULL;
        unsigned int usernmlen;
        cbsasl_secret_t *pass;

        cbsasl_error_t ret;
        ret = conn->c.client.get_username(conn->c.client.get_username_ctx,
                                          CBSASL_CB_USER,
                                          &usernm, &usernmlen);
        if (ret != SASL_OK) {
            return ret;
        }

        ret = conn->c.client.get_password(conn, conn->c.client.get_password_ctx,
                                          CBSASL_CB_PASS,
                                          &pass);
        if (ret != SASL_OK) {
            return ret;
        }

        conn->c.client.userdata = calloc(usernmlen + 1 + pass->len + 1, 1);
        if (conn->c.client.userdata == NULL) {
            return SASL_NOMEM;
        }

        memcpy(conn->c.client.userdata + 1, usernm, usernmlen);
        memcpy(conn->c.client.userdata + usernmlen + 2, pass->data, pass->len);
        *clientout = conn->c.client.userdata;
        *clientoutlen = (unsigned int)(usernmlen + 2 + pass->len);
    } else {
        /* CRAM-MD5 */
        *clientout = NULL;
        *clientoutlen = 0;
    }

    (void)prompt_need;
    return SASL_OK;
}

CBSASL_PUBLIC_API
cbsasl_error_t cbsasl_client_step(cbsasl_conn_t *conn,
                                  const char *serverin,
                                  unsigned int serverinlen,
                                  void **not_used,
                                  const char **clientout,
                                  unsigned int *clientoutlen)
{
    unsigned char digest[DIGEST_LENGTH];
    char md5string[DIGEST_LENGTH * 2];
    const char *usernm = NULL;
    unsigned int usernmlen;
    cbsasl_secret_t *pass;
    cbsasl_error_t ret;

    if (conn->client == 0) {
        return SASL_BADPARAM;
    }

    if (conn->c.client.plain) {
        /* Shouldn't be called during plain auth */
        return SASL_BADPARAM;
    }

    ret = conn->c.client.get_username(conn->c.client.get_username_ctx,
                                      CBSASL_CB_USER, &usernm, &usernmlen);
    if (ret != SASL_OK) {
        return ret;
    }

    ret = conn->c.client.get_password(conn, conn->c.client.get_password_ctx,
                                      CBSASL_CB_PASS, &pass);
    if (ret != SASL_OK) {
        return ret;
    }

    free(conn->c.client.userdata);
    conn->c.client.userdata = calloc(usernmlen + 1 + sizeof(md5string) + 1, 1);
    if (conn->c.client.userdata == NULL) {
        return SASL_NOMEM;
    }

    hmac_md5((unsigned char*)serverin, serverinlen, pass->data,
             pass->len, digest);
    cbsasl_hex_encode(md5string, (char *) digest, DIGEST_LENGTH);
    memcpy(conn->c.client.userdata, usernm, usernmlen);
    conn->c.client.userdata[usernmlen] = ' ';
    memcpy(conn->c.client.userdata + usernmlen + 1, md5string,
           sizeof(md5string));

    *clientout = conn->c.client.userdata;
    *clientoutlen = strlen(conn->c.client.userdata);

    return SASL_CONTINUE;
}
