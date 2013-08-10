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
#ifndef SRC_INTERNAL_H
#define SRC_INTERNAL 1

#include "config.h"
#include <cbsasl/cbsasl.h>

typedef struct cbsasl_mechs {
    const char* name;
    cbsasl_init_fn init;
    cbsasl_start_fn start;
    cbsasl_step_fn step;
} cbsasl_mechs_t;

struct cbsasl_conn_t {
    char* username;
    char* config;
    char* sasl_data;
    unsigned sasl_data_len;
    cbsasl_mechs_t mech;
};

#endif /* SRC_INTERNAL_H */
