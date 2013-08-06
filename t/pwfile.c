
#include "config.h"
#include "pwfile.h"

const char* cbpwfile = "/tmp/pwfile_test.pw";

const char* user1 = "mikewied";
const char* pass1 = "mikepw";
const char* user2 = "cseo";
const char* pass2 = "seopw";
const char* user3 = "jlim";
const char* pass3 = "limpw";

static void create_pw_file() {
    FILE *fp = fopen(cbpwfile, "w");
    assert(fp != NULL);

    fprintf(fp, "mikewied mikepw \ncseo seopw \njlim limpw \n");
    assert(fclose(fp) == 0);

    putenv("ISASL_PWFILE=/tmp/pwfile_test.pw");
}

static void remove_pw_file() {
    assert(remove(cbpwfile) == 0);
}

static void test_pwile() {
    char* cfg;

    create_pw_file();
    assert(load_user_db() == SASL_OK);
    char* password = find_pw(user1, &cfg);
    assert(strncmp(password, pass1, strlen(pass1)) == 0);

    password = find_pw(user2, &cfg);
    assert(strncmp(password, pass2, strlen(pass2)) == 0);

    password = find_pw(user3, &cfg);
    assert(strncmp(password, pass3, strlen(pass3)) == 0);

    remove_pw_file();
}

int main() {
    test_pwile();
    return 0;
}