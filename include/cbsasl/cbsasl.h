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

#ifndef INCLUDE_CBSASL_CBSASL_H_
#define INCLUDE_CBSASL_CBSASL_H_ 1

typedef enum cbsasl_param {
    CBSASL_PARAM_USERNAME,
    CBSASL_PARAM_PASSWORD,
    CBSASL_PARAM_CONFIG
} cbsasl_param_t;

typedef enum cbsasl_error {
    SASL_OK,
    SASL_CONTINUE,
    SASL_FAIL,
    SASL_NOMEM,
    SASL_BADPARAM,
    SASL_NOUSER
} cbsasl_error_t;

typedef struct cbsasl_callback {
    unsigned long id;
    int (*proc)(void);
    void *context;
} cbsasl_callback_t;

typedef struct cbsasl_conn {
    char *username;
    char *config;
} cbsasl_conn_t;

void init_sasl(void);

void sasl_dispose(cbsasl_conn_t **pconn);

cbsasl_error_t sasl_server_init();

cbsasl_error_t sasl_server_new(const char *service,
                               const char *serverFQDN,
                               const char *user_realm,
                               const char *iplocalport,
                               const char *ipremoteport,
                               const cbsasl_callback_t *callbacks,
                               unsigned flags,
                               cbsasl_conn_t **pconn);

cbsasl_error_t sasl_listmech(cbsasl_conn_t *conn,
                             const char *user,
                             const char *prefix,
                             const char *sep,
                             const char *suffix,
                             const char **result,
                             unsigned *plen,
                             int *pcount);

cbsasl_error_t sasl_server_start(cbsasl_conn_t *conn,
                                 const char *mech,
                                 const char *clientin,
                                 unsigned clientinlen,
                                 const char **serverout,
                                 unsigned *serveroutlen);

cbsasl_error_t sasl_server_step(cbsasl_conn_t *conn,
                                const char *clientin,
                                unsigned clientinlen,
                                const char **serverout,
                                unsigned *serveroutlen);

cbsasl_error_t sasl_getprop(cbsasl_conn_t *conn,
                            cbsasl_param_t param,
                            const void **pvalue);

#endif  // INCLUDE_CBSASL_CBSASL_H_
