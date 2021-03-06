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

/**
 * All of the hmac-md5 test cases have be written base on the defined test cases
 * in rfc 2202. http://tools.ietf.org/html/draft-cheng-hmac-test-cases-00
 */

#include "cram-md5/hmac.h"
#include <platform/platform.h>
#include <string.h>

static void test1()
{
    unsigned char key[16] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                             0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
                            };
    unsigned char *data = (unsigned char *)"Hi There";
    unsigned char digest[DIGEST_LENGTH] = {0x92, 0x94, 0x72, 0x7a,
                                           0x36, 0x38, 0xbb, 0x1c,
                                           0x13, 0xf4, 0x8e, 0xf8,
                                           0x15, 0x8b, 0xfc, 0x9d
                                          };

    unsigned char new_digest[DIGEST_LENGTH];
    hmac_md5(data, 8, key, 16, new_digest);
    cb_assert(memcmp(digest, new_digest, DIGEST_LENGTH) == 0);
}

static void test2()
{
    unsigned char *key = (unsigned char *)"Jefe";
    unsigned char *data = (unsigned char *)"what do ya want for nothing?";

    unsigned char digest[DIGEST_LENGTH] = {0x75, 0x0c, 0x78, 0x3e,
                                           0x6a, 0xb0, 0xb5, 0x03,
                                           0xea, 0xa8, 0x6e, 0x31,
                                           0x0a, 0x5d, 0xb7, 0x38
                                          };

    unsigned char new_digest[DIGEST_LENGTH];
    hmac_md5(data, 28, key, 4, new_digest);
    cb_assert(memcmp(digest, new_digest, DIGEST_LENGTH) == 0);
}

static void test3()
{
    unsigned char key[16] = {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                             0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa
                            };
    unsigned char data[50] = {0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
                              0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
                              0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
                              0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
                              0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
                              0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
                              0xdd, 0xdd
                             };
    unsigned char digest[DIGEST_LENGTH] = {0x56, 0xbe, 0x34, 0x52,
                                           0x1d, 0x14, 0x4c, 0x88,
                                           0xdb, 0xb8, 0xc7, 0x33,
                                           0xf0, 0xe8, 0xb3, 0xf6
                                          };

    unsigned char new_digest[DIGEST_LENGTH];
    hmac_md5(data, 50, key, 16, new_digest);
    cb_assert(memcmp(digest, new_digest, DIGEST_LENGTH) == 0);
}

static void test4()
{
    unsigned char key[25] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                             0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                             0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                             0x19
                            };
    unsigned char data[50] = {0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
                              0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
                              0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
                              0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
                              0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
                              0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
                              0xcd, 0xcd
                             };
    unsigned char digest[DIGEST_LENGTH] = {0x69, 0x7e, 0xaf, 0x0a,
                                           0xca, 0x3a, 0x3a, 0xea,
                                           0x3a, 0x75, 0x16, 0x47,
                                           0x46, 0xff, 0xaa, 0x79
                                          };

    unsigned char new_digest[DIGEST_LENGTH];
    hmac_md5(data, 50, key, 25, new_digest);
    cb_assert(memcmp(digest, new_digest, DIGEST_LENGTH) == 0);
}

static void test5()
{
    unsigned char key[16] = {0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
                             0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c
                            };
    unsigned char *data = (unsigned char *)"Test With Truncation";
    unsigned char digest[DIGEST_LENGTH] = {0x56, 0x46, 0x1e, 0xf2,
                                           0x34, 0x2e, 0xdc, 0x00,
                                           0xf9, 0xba, 0xb9, 0x95,
                                           0x69, 0x0e, 0xfd, 0x4c
                                          };

    unsigned char new_digest[DIGEST_LENGTH];
    hmac_md5(data, 20, key, 16, new_digest);
    cb_assert(memcmp(digest, new_digest, DIGEST_LENGTH) == 0);
}

static void test6()
{
    unsigned char key[80] = {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                             0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                             0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                             0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                             0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                             0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                             0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                             0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                             0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                             0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa
                            };
    unsigned char *data = (unsigned char *)"Test Using Larger Than Block-Size Key - "
                          "Hash Key First";
    unsigned char digest[DIGEST_LENGTH] = {0x6b, 0x1a, 0xb7, 0xfe,
                                           0x4b, 0xd7, 0xbf, 0x8f,
                                           0x0b, 0x62, 0xe6, 0xce,
                                           0x61, 0xb9, 0xd0, 0xcd
                                          };

    unsigned char new_digest[DIGEST_LENGTH];
    hmac_md5(data, 54, key, 80, new_digest);
    cb_assert(memcmp(digest, new_digest, DIGEST_LENGTH) == 0);
}

static void test7()
{
    unsigned char key[80] = {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                             0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                             0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                             0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                             0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                             0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                             0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                             0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                             0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                             0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa
                            };
    unsigned char *data = (unsigned char *)"Test Using Larger Than Block-Size Key"
                          " and Larger Than One Block-Size Data";
    unsigned char digest[DIGEST_LENGTH] = {0x6f, 0x63, 0x0f, 0xad,
                                           0x67, 0xcd, 0xa0, 0xee,
                                           0x1f, 0xb1, 0xf5, 0x62,
                                           0xdb, 0x3a, 0xa5, 0x3e
                                          };

    unsigned char new_digest[DIGEST_LENGTH];
    hmac_md5(data, 73, key, 80, new_digest);
    cb_assert(memcmp(digest, new_digest, DIGEST_LENGTH) == 0);
}

int main()
{
    test1();
    test2();
    test3();
    test4();
    test5();
    test6();
    test7();
    return 0;
}
