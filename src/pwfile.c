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

#include "hash.h"
#include "pwfile.h"

typedef struct user_db_entry {
    char *username;
    char *password;
    char *config;
    struct user_db_entry *next;
    struct user_db_entry *prev;
} user_db_entry_t;

static user_db_entry_t *user_db;

static pthread_mutex_t user_db_mutex = PTHREAD_MUTEX_INITIALIZER;

static user_db_entry_t *destroy_user_entry(user_db_entry_t *e) {
    user_db_entry_t *ret = e->next;
    free(e->username);
    free(e->password);
    free(e->config);
    free(e);
    return ret;
}

CBSASL_PUBLIC_API
cbsasl_error_t cbsasl_destroy_creds(void) {
    user_db_entry_t *p = user_db;

    pthread_mutex_lock(&user_db_mutex);
    while (p) {
        p = destroy_user_entry(p);
    }
    pthread_mutex_unlock(&user_db_mutex);
}

/**
 * Search for a given user in the sorted linked list of users..
 *
 * @param u the user to search for
 * @return the user we search for, _OR_ the user before
 */
static user_db_entry_t *search(const char *u) {
    user_db_entry_t *s = user_db;
    user_db_entry_t *prev = NULL;

    while (s && strcmp(u, s->username) > 0) {
        prev = s;
        s = s->next;
    }

    /* If we moved all the way to the end, let's return the last element */
    if (s == NULL) {
        return prev;
    }

    return s;
}

/* @todo this is not safe!!! */
char *find_pw(const char *u, char **cfg) {
    user_db_entry_t *e;
    char *ret = NULL;

    pthread_mutex_lock(&user_db_mutex);
    if ((e = search(u)) != NULL && strcmp(e->username, u) == 0) {
        ret = e->password;
        if (cfg) {
            *cfg = e->config;
        }
    }

    pthread_mutex_unlock(&user_db_mutex);
    return ret;
}

CBSASL_PUBLIC_API
cbsasl_error_t cbsasl_update_cred(const char *username,
                                  const char *password,
                                  const char *config)
{
    int h;
    user_db_entry_t *e;
    user_db_entry_t *s;

    if (username == NULL) {
        return SASL_BADPARAM;
    }

    if ((e = calloc(1, sizeof(user_db_entry_t))) == NULL) {
        return SASL_NOMEM;
    }

    if (((e->username = strdup(username)) == NULL) ||
        (password && (e->password = strdup(password)) == NULL) ||
        (config && (e->config = strdup(config)) == NULL)) {
        destroy_user_entry(e);
        return SASL_NOMEM;
    }

    pthread_mutex_lock(&user_db_mutex);
    s = search(username);
    if (s) {
        int pos = strcmp(username, s->username);
        if (pos == 0) {
            e->next = s->next;
            e->prev = s->prev;
            if (e->next) {
                e->next->prev = e;
            }
            if (e->prev) {
                e->prev->next = e;
            }
            destroy_user_entry(s);
        } else if (pos < 0) {
            e->next = s;
            e->prev = s->prev;
            s->prev = e;
            if (e->prev) {
                e->prev->next = e;
            } else {
                /* must be first */
                user_db = e;
            }
        } else {
            e->next = s->next;
            if (e->next) {
                e->next->prev = e;
            }
            s->next = e;
            e->prev = s;
        }
    } else {
        user_db = e;
    }

    pthread_mutex_unlock(&user_db_mutex);

    return SASL_OK;
}

/**
 * Delete a user.
 *
 * @param username the name of the user (must be terminated with \0)
 *
 * @return SASL_OK for success
 */
CBSASL_PUBLIC_API
cbsasl_error_t cbsasl_remove_cred(const char *username) {
    user_db_entry_t *s;
    pthread_mutex_lock(&user_db_mutex);
    s = search(username);
    if (s && strcmp(s->username, username) == 0) {
        if (s->prev) {
            s->prev->next = s->next;
        } else {
            /* First node */
            user_db = s->next;
        }

        if (s->next) {
            s->next->prev = s->prev;
        }
        destroy_user_entry(s);
    }

    pthread_mutex_unlock(&user_db_mutex);

    return SASL_OK;
}
