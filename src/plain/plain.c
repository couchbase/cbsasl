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
#include "plain.h"
#include "pwfile.h"

cbsasl_error_t plain_server_init() {
    return SASL_OK;
}

cbsasl_error_t plain_server_start(cbsasl_conn_t* conn) {
    conn->sasl_data = NULL;
    conn->sasl_data_len = 0;
    return SASL_CONTINUE;
}

cbsasl_error_t plain_server_step(cbsasl_conn_t *conn,
                                 const char* input,
                                 unsigned inputlen,
                                 const char** output,
                                 unsigned* outputlen) {

    while (inputlen > 0 && input[0] != '\0') {
        // Skip authzid
        input++;
        inputlen--;
    }
    if (inputlen > 2 && inputlen < 128 && input[0] == '\0') {
        const char *username = input + 1;
        char password[256];
        int pwlen = inputlen - 2 - strlen(username);

        if (pwlen < 0) {
            return SASL_BADPARAM;
        }
        if (pwlen < 256) {
            char *cfg = NULL;
            password[pwlen] = '\0';
            memcpy(password, input + 2 + strlen(username), pwlen);

            char* pwd = find_pw(username, &cfg);
            if (pwd == NULL) {
                return SASL_FAIL;
            }

            if (memcmp(password, pwd, strlen(pwd)) != 0) {
                return SASL_FAIL;
            }
            conn->username = strdup(username);
            conn->config = strdup(cfg);
        }
    }
    *output = NULL;
    *outputlen = 0;
    return SASL_OK;
}

cbsasl_mechs_t get_plain_mechs(void) {
    static cbsasl_mechs_t mechs = {
        MECH_NAME_PLAIN,
        plain_server_init,
        plain_server_start,
        plain_server_step
    };
    return mechs;
}
