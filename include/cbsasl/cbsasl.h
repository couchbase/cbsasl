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

#include <cbsasl/visibility.h>

typedef enum cbsasl_error {
    SASL_OK,
    SASL_CONTINUE,
    SASL_FAIL,
    SASL_NOMEM,
    SASL_BADPARAM,
    SASL_NOUSER
} cbsasl_error_t;

typedef struct cbsasl_conn_t cbsasl_conn_t;

typedef cbsasl_error_t (*cbsasl_init_fn)();
typedef cbsasl_error_t (*cbsasl_start_fn)(cbsasl_conn_t*);
typedef cbsasl_error_t (*cbsasl_step_fn)(cbsasl_conn_t*, const char*,
                                         unsigned, const char**, unsigned*);

/**
 * Lists all of the mechanisms this sasl server supports
 *
 * @param mechs A string containing all supported mechanism names
 * @param mechslen The length of the mechs string
 *
 * @return Whether or not an error occured while getting the mechanism list
 */
CBSASL_PUBLIC_API
cbsasl_error_t cbsasl_list_mechs(const char **mechs, unsigned *mechslen);

/**
 * Initializes the sasl server
 *
 * This function initializes the server by loading passwords from the cbsasl
 * password file. This function should only be called once.
 *
 * @return Whether or not the sasl server initialization was successful
 */
CBSASL_PUBLIC_API
cbsasl_error_t cbsasl_init();

/**
 * Creates a sasl connection and begins authentication
 *
 * When a client receives a request for sasl authentication this function is
 * called in order to initialize the sasl connection based on the mechanism
 * specified.
 *
 * @param conn The connection context for this session
 * @param mechanism The mechanism that will be used for authentication
 *
 * @return Whether or not the mecahnism initialization was successful
 */
CBSASL_PUBLIC_API
cbsasl_error_t cbsasl_start(cbsasl_conn_t **conn, const char* mechanism);

/**
 * Does username/password authentication
 *
 * After the sasl connection is initialized the step function is called to
 * check credentials.
 *
 * @return Whether or not the sasl step was successful
 */
CBSASL_PUBLIC_API
cbsasl_error_t cbsasl_step(cbsasl_conn_t *conn,
                           const char* input,
                           unsigned inputlen,
                           const char** output,
                           unsigned* outputlen);

/**
 * Frees up funushed sasl connections
 *
 * @param conn The sasl connection to free
 */
CBSASL_PUBLIC_API
void cbsasl_dispose(cbsasl_conn_t **pconn);


/* The following methods is used for password maintenance on the server */

/**
 * Add or update the username/password combination
 *
 * @param username the name of the user (must be terminated with \0)
 * @param password the password for the user (must be terminated with \0);
 * @param config an opaque string stored with the user (must be
 *               terminated with \0)
 *
 * @return SASL_OK for success
 */
CBSASL_PUBLIC_API
cbsasl_error_t cbsasl_update_cred(const char *username,
                                  const char *password,
                                  const char *config);

/**
 * Delete a user.
 *
 * @param username the name of the user (must be terminated with \0)
 *
 * @return SASL_OK for success
 */
CBSASL_PUBLIC_API
cbsasl_error_t cbsasl_remove_cred(const char *username);

/**
 * Destroy all credentials
 */
CBSASL_PUBLIC_API
cbsasl_error_t cbsasl_destroy_creds(void);


#endif  /* INCLUDE_CBSASL_CBSASL_H_ */
