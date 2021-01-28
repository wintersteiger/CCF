add_picobench(
  signature_bench_host
  SRCS src/crypto/test/signature_bench.cpp
  LINK_LIBS ccfcrypto.host
)

set(EDL_FILE ${CMAKE_CURRENT_LIST_DIR}/signature_bench.edl)
set(CFG_FILE ${CMAKE_CURRENT_LIST_DIR}/signature_bench.cfg)
set(KEY_FILE ${CMAKE_CURRENT_BINARY_DIR}/signing_key.pem)

# Enclave

add_custom_command(
  OUTPUT signature_bench_t.h signature_bench_t.c
  DEPENDS ${EDL_FILE} openenclave::oeedger8r
  COMMAND
    openenclave::oeedger8r --trusted ${EDL_FILE} --search-path ${OE_INCLUDEDIR})

add_library(signature_bench SHARED
  src/crypto/test/signature_bench.cpp
  src/crypto/hash.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/signature_bench_t.c
)

target_compile_definitions(signature_bench PRIVATE HAVE_OPENSSL)
target_include_directories(signature_bench PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(signature_bench ${OE_TARGET_ENCLAVE_AND_STD} -lgcc)

add_custom_command(
  OUTPUT ${KEY_FILE}
  COMMAND openssl genrsa -out ${KEY_FILE} -3 3072
)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/libsignature_bench.signed
    COMMAND openenclave::oesign sign -e ${CMAKE_CURRENT_BINARY_DIR}/libsignature_bench.so
            -c ${CFG_FILE} -k ${KEY_FILE}
    DEPENDS signature_bench ${KEY_FILE}
  )


# Runner
add_custom_command(
  OUTPUT signature_bench_u.h signature_bench_u.c
  DEPENDS ${EDL_FILE} openenclave::oeedger8r ${CMAKE_CURRENT_BINARY_DIR}/libsignature_bench.signed
  COMMAND
    openenclave::oeedger8r --untrusted ${EDL_FILE} --search-path ${OE_INCLUDEDIR})

add_executable(signature_bench_runner
  src/crypto/test/signature_bench_runner.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/signature_bench_u.c
)

target_include_directories(signature_bench_runner PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${OE_INCLUDEDIR})
target_link_libraries(signature_bench_runner openenclave::oehost openenclave::oehostverify)