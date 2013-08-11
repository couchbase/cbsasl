#include "cbsasl/cbsasl.h"
#include "config.h"
#include "pwfile.h"

const char* user1 = "mikewied";
const char* pass1 = "mikepw";
const char* user2 = "cseo";
const char* pass2 = "seopw";
const char* user3 = "jlim";
const char* pass3 = "limpw";

static void create_pwdb(void) {
    assert(cbsasl_update_cred(user3, pass3, NULL) == SASL_OK);
    assert(cbsasl_update_cred(user1, pass1, NULL) == SASL_OK);
    assert(cbsasl_update_cred(user2, pass2, NULL) == SASL_OK);
}

static void remove_pwdb(void) {
    assert(cbsasl_remove_cred(user3) == SASL_OK);
    assert(cbsasl_remove_cred(user1) == SASL_OK);
    assert(cbsasl_remove_cred(user2) == SASL_OK);
    cbsasl_destroy_creds();
}

static void test_pwfile(void) {
    char cfg[256];
    char password[256];

    create_pwdb();

    assert(find_pw(user1, password, sizeof(password), cfg, sizeof(cfg)));
    assert(strncmp(password, pass1, strlen(pass1)) == 0);
    assert(*cfg == '\0');

    assert(find_pw(user2, password, sizeof(password), cfg, sizeof(cfg)));
    assert(strncmp(password, pass2, strlen(pass2)) == 0);
    assert(*cfg == '\0');

    assert(find_pw(user3, password, sizeof(password), cfg, sizeof(cfg)));
    assert(strncmp(password, pass3, strlen(pass3)) == 0);
    assert(*cfg == '\0');

    remove_pwdb();
}

int main(void) {
    test_pwfile();
    return 0;
}
