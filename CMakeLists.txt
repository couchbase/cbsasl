CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

ADD_DEFINITIONS(-D_CRT_NONSTDC_NO_DEPRECATE)
ADD_DEFINITIONS(-D_CRT_SECURE_NO_WARNINGS)

SET(cbsasl_sources
                   include/cbsasl/cbsasl.h
                   include/cbsasl/visibility.h
                   src/client.c
                   src/common.c
                   src/cram-md5/cram-md5.c
                   src/cram-md5/cram-md5.h
                   src/cram-md5/hmac.c
                   src/cram-md5/hmac.h
                   src/cram-md5/md5.c
                   src/cram-md5/md5.h
                   src/hash.c
                   src/hash.h
                   src/plain/plain.c
                   src/plain/plain.h
                   src/pwfile.c
                   src/pwfile.h
                   src/server.c
                   src/strcmp.c
                   src/util.h)

ADD_LIBRARY(cbsasl SHARED ${cbsasl_sources})
SET_TARGET_PROPERTIES(cbsasl PROPERTIES SOVERSION 1.1.1)
SET_TARGET_PROPERTIES(cbsasl PROPERTIES COMPILE_FLAGS -DBUILDING_CBSASL=1)
SET_TARGET_PROPERTIES(cbsasl PROPERTIES INSTALL_NAME_DIR ${CMAKE_INSTALL_PREFIX}/lib)

INCLUDE_DIRECTORIES(BEFORE ${CMAKE_CURRENT_SOURCE_DIR}/include
                           ${CMAKE_CURRENT_SOURCE_DIR}/src
                           ${CMAKE_CURRENT_SOURCE_DIR}/../platform/include
                           ${CMAKE_INSTALL_PREFIX}/include)

IF (INSTALL_HEADER_FILES)
INSTALL(FILES
        include/cbsasl/cbsasl.h
        include/cbsasl/visibility.h
        DESTINATION include/cbsasl)
ENDIF(INSTALL_HEADER_FILES)

INSTALL(TARGETS cbsasl
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib)

ADD_EXECUTABLE(cbsasl_hmac_test tests/hmac_test.c
                                src/cram-md5/hmac.c
                                src/cram-md5/hmac.h
                                src/cram-md5/md5.c
                                src/cram-md5/md5.h)

ADD_EXECUTABLE(cbsasl_pwfile_test tests/pwfile_test.c
                                  src/pwfile.c
                                  src/pwfile.h
                                  src/hash.c
                                  src/hash.h)

# We're using an "internal api" of the library in the test so we can't
# use the library we just built
ADD_EXECUTABLE(sasl_test tests/sasl_server_test.c ${cbsasl_sources})
SET_TARGET_PROPERTIES(sasl_test PROPERTIES COMPILE_FLAGS -DBUILDING_CBSASL=1)

ADD_EXECUTABLE(cbsasl_test tests/cbsasl_test.c
                           include/cbsasl/cbsasl.h
                           include/cbsasl/visibility.h)
TARGET_LINK_LIBRARIES(cbsasl_test cbsasl)

TARGET_LINK_LIBRARIES(cbsasl platform)
TARGET_LINK_LIBRARIES(cbsasl_pwfile_test platform)
TARGET_LINK_LIBRARIES(sasl_test platform)

ADD_EXECUTABLE(cbsasl_strcmp_test tests/strcmp_test.c
                                  include/cbsasl/cbsasl.h
                                  include/cbsasl/visibility.h
                                  src/strcmp.c)

ADD_TEST(cbsasl-hmac cbsasl_hmac_test)
ADD_TEST(cbsasl-pwfile cbsasl_pwfile_test)
ADD_TEST(cbsasl-sasl sasl_test)
ADD_TEST(cbsasl-client-server cbsasl_test)
ADD_TEST(cbsasl-strcmp cbsasl_strcmp_test)

ADD_CUSTOM_TARGET(reformat-cbsasl-source
                  COMMAND astyle ${ASTYLE_CFLAGS}
                  VERBATIM)
