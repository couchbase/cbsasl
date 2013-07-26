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
#include "pwfile.h"

#define SASL_CB_LIST_END 0

void init_sasl(void) {
    if (sasl_server_init() != SASL_OK) {
        /*settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                                        "Error initializing sasl.");*/
        exit(EXIT_FAILURE);
    } /*else {
        if (settings.verbose) {
            settings.extensions.logger->log(EXTENSION_LOG_INFO, NULL,
                                            "Initialized SASL.");
        }
    }*/
}

void sasl_dispose(cbsasl_conn_t **pconn)
{
    free((*pconn)->username);
    free((*pconn)->config);
    free(*pconn);
    *pconn = NULL;
}

void shutdown_sasl(void) {

}

cbsasl_error_t sasl_server_init() {
    return load_user_db();
}

cbsasl_error_t sasl_server_new(const char *service,
                               const char *serverFQDN,
                               const char *user_realm,
                               const char *iplocalport,
                               const char *ipremoteport,
                               const cbsasl_callback_t *callbacks,
                               unsigned flags,
                               cbsasl_conn_t **pconn) {
    *pconn = calloc(1, sizeof(cbsasl_conn_t));
    return *pconn ? SASL_OK : SASL_NOMEM;
}

cbsasl_error_t sasl_listmech(cbsasl_conn_t *conn,
                             const char *user,
                             const char *prefix,
                             const char *sep,
                             const char *suffix,
                             const char **result,
                             unsigned *plen,
                             int *pcount) {
    // We use this in a very specific way in the codebase.  If that ever
    // changes, detect it quickly.
    assert(strcmp(prefix, "") == 0);
    assert(strcmp(sep, " ") == 0);
    assert(strcmp(suffix, "") == 0);

    *result = "PLAIN";
    *plen = strlen(*result);
    return SASL_OK;
}

cbsasl_error_t sasl_server_start(cbsasl_conn_t *conn,
                                 const char *mech,
                                 const char *clientin,
                                 unsigned clientinlen,
                                 const char **serverout,
                                 unsigned *serveroutlen) {
    int rv = SASL_FAIL;
    *serverout = "";
    *serveroutlen = 0;

    if(strcmp(mech, "PLAIN") == 0) {
        // The clientin string looks like "[authzid]\0username\0password"
        while (clientinlen > 0 && clientin[0] != '\0') {
            // Skip authzid
            clientin++;
            clientinlen--;
        }
        if (clientinlen > 2 && clientinlen < 128 && clientin[0] == '\0') {
            const char *username = clientin + 1;
            char password[256];
            int pwlen = clientinlen - 2 - strlen(username);
            assert(pwlen >= 0);
            if (pwlen < 256) {
                char *cfg = NULL;
                password[pwlen] = '\0';
                memcpy(password, clientin + 2 + strlen(username), pwlen);

                if (check_up(username, password, &cfg)) {
                    if (conn->username) {
                        free(conn->username);
                        conn->username = NULL;
                    }
                    if (conn->config) {
                        free(conn->config);
                        conn->config = NULL;
                    }
                    conn->username = strdup(username);
                    assert(conn->username);
                    conn->config = strdup(cfg);
                    assert(conn->config);
                    rv = SASL_OK;
                }
            }
        }
    }

    return rv;
}

cbsasl_error_t sasl_server_step(cbsasl_conn_t *conn,
                                const char *clientin,
                                unsigned clientinlen,
                                const char **serverout,
                                unsigned *serveroutlen) {
    // This is only useful when the above returns SASL_CONTINUE.  In this
    // implementation, only PLAIN is supported, so it never will.
    return SASL_FAIL;
}

cbsasl_error_t sasl_getprop(cbsasl_conn_t *conn,
                            cbsasl_param_t param,
                            const void **pvalue) {
    switch (param) {
        case CBSASL_PARAM_USERNAME:
            *pvalue = conn->username;
            break;
        case CBSASL_PARAM_CONFIG:
            *pvalue = conn->config;
            break;
        default:
            return SASL_BADPARAM;
    }

    return SASL_OK;
}
