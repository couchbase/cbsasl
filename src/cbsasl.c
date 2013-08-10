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
#include "plain/plain.h"
#include "pwfile.h"
#include <time.h>

#define IS_MECH(str, mech) (strncmp(str, mech, strlen(mech)))

cbsasl_error_t cbsasl_list_mechs(const char **mechs,
                                 unsigned *mechslen) {
    *mechs = "CRAM-MD5 PLAIN";
    *mechslen = strlen(*mechs);
    return SASL_OK;
}

CBSASL_PUBLIC_API
cbsasl_error_t cbsasl_init() {
    srand(getpid());
    return load_user_db();
}

CBSASL_PUBLIC_API
cbsasl_error_t cbsasl_start(cbsasl_conn_t **conn,
                            const char* mech) {
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
        memcpy(&(*conn)->mech, &plain_mech, sizeof(cbsasl_mechs_t));
    } else if (IS_MECH(mech, MECH_NAME_CRAM_MD5) == 0) {
        cbsasl_mechs_t cram_md5_mech = get_cram_md5_mechs();
        memcpy(&(*conn)->mech, &cram_md5_mech, sizeof(cbsasl_mechs_t));
    } else {
        return SASL_BADPARAM;
    }

    if ((err = (*conn)->mech.init()) != SASL_OK) {
        return err;
    }

    return (*conn)->mech.start(*conn);
}

CBSASL_PUBLIC_API
cbsasl_error_t cbsasl_step(cbsasl_conn_t *conn,
                           const char* input,
                           unsigned inputlen,
                           const char** output,
                           unsigned* outputlen) {
    return conn->mech.step(conn, input, inputlen, output, outputlen);
}

CBSASL_PUBLIC_API
void cbsasl_dispose(cbsasl_conn_t **conn) {
    if (*conn != NULL) {
        free((*conn)->username);
        free((*conn)->config);
        free((*conn)->sasl_data);
        free(*conn);
        *conn = NULL;
    }
}
