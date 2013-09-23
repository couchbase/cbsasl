CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

ADD_DEFINITIONS(-D_CRT_NONSTDC_NO_DEPRECATE)

SET(cbsasl_sources src/cbsasl.c
            src/cram-md5/cram-md5.c
            src/cram-md5/hmac.c
            src/hash.c
            src/cram-md5/md5.c
            src/plain/plain.c
            src/pwfile.c)

ADD_LIBRARY(cbsasl SHARED ${cbsasl_sources})
SET_TARGET_PROPERTIES(cbsasl PROPERTIES SOVERSION 1.1.1)
SET_TARGET_PROPERTIES(cbsasl PROPERTIES COMPILE_FLAGS -DBUILDING_CBSASL=1)
SET_TARGET_PROPERTIES(cbsasl PROPERTIES INSTALL_NAME_DIR ${CMAKE_INSTALL_PREFIX}/lib)

INCLUDE_DIRECTORIES(BEFORE ${CMAKE_CURRENT_SOURCE_DIR}/include
                           ${CMAKE_CURRENT_SOURCE_DIR}/src
                           ${CMAKE_CURRENT_SOURCE_DIR}/../platform/include
                           ${CMAKE_INSTALL_PREFIX}/include)

INSTALL(FILES
        include/cbsasl/cbsasl.h
        include/cbsasl/visibility.h
        DESTINATION include/cbsasl)

INSTALL(TARGETS cbsasl
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib)

ADD_EXECUTABLE(hmac_test t/hmac_test.c src/cram-md5/hmac.c src/cram-md5/md5.c)
ADD_EXECUTABLE(pwfile_test t/pwfile.c src/pwfile.c src/hash.c)

# We're using an "internal api" of the library in the test so we can't
# use the library we just built
ADD_EXECUTABLE(sasl_test t/sasl_server_test.c ${cbsasl_sources})
SET_TARGET_PROPERTIES(sasl_test PROPERTIES COMPILE_FLAGS -DBUILDING_CBSASL=1)

ADD_EXECUTABLE(cbsasl_test t/cbsasl_test.c)
TARGET_LINK_LIBRARIES(cbsasl_test cbsasl)

TARGET_LINK_LIBRARIES(cbsasl platform)
TARGET_LINK_LIBRARIES(pwfile_test platform)
TARGET_LINK_LIBRARIES(sasl_test platform)

ADD_TEST(hmac hmac_test)
ADD_TEST(pwfile pwfile_test)
ADD_TEST(sasl sasl_test)
ADD_TEST(client-server cbsasl_test)

ADD_CUSTOM_TARGET(reformat-cbsasl-source
                  COMMAND astyle ${ASTYLE_CFLAGS}
                  VERBATIM)
