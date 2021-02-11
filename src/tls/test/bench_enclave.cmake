set(EDL_FILE ${CMAKE_CURRENT_LIST_DIR}/tls_bench.edl)
set(CFG_FILE ${CMAKE_CURRENT_LIST_DIR}/tls_bench.cfg)
set(KEY_FILE ${CMAKE_CURRENT_BINARY_DIR}/signing_key.pem)

# Enclave

add_custom_command(
  OUTPUT tls_bench_t.h tls_bench_t.c
  DEPENDS ${EDL_FILE} openenclave::oeedger8r
  COMMAND
    openenclave::oeedger8r --trusted ${EDL_FILE} --search-path ${OE_INCLUDEDIR})

add_library(tls_bench_enclave SHARED
  src/tls/test/bench.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/tls_bench_t.c
)

target_compile_definitions(tls_bench_enclave PRIVATE HAVE_OPENSSL)
target_include_directories(tls_bench_enclave PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(tls_bench_enclave ${OE_TARGET_ENCLAVE_AND_STD} -lgcc)

add_custom_command(
  OUTPUT ${KEY_FILE}
  COMMAND openssl genrsa -out ${KEY_FILE} -3 3072
)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/libtls_bench_enclave.signed
    COMMAND openenclave::oesign sign -e ${CMAKE_CURRENT_BINARY_DIR}/libtls_bench_enclave.so
            -c ${CFG_FILE} -k ${KEY_FILE}
    DEPENDS tls_bench_enclave ${KEY_FILE}
  )


# Runner
add_custom_command(
  OUTPUT tls_bench_u.h tls_bench_u.c
  DEPENDS ${EDL_FILE} openenclave::oeedger8r ${CMAKE_CURRENT_BINARY_DIR}/libtls_bench_enclave.signed
  COMMAND
    openenclave::oeedger8r --untrusted ${EDL_FILE} --search-path ${OE_INCLUDEDIR})

add_executable(tls_bench_runner
  src/tls/test/tls_bench_runner.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/tls_bench_u.c
)

target_include_directories(tls_bench_runner PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${OE_INCLUDEDIR})
target_link_libraries(tls_bench_runner openenclave::oehost openenclave::oehostverify)