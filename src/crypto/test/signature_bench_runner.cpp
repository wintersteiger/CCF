#include <openenclave/host.h>
#include <signature_bench_u.h>

int main(void)
{
  oe_result_t result = OE_UNEXPECTED;
  oe_enclave_t* enclave = NULL;

  oe_create_signature_bench_enclave(
    "libsignature_bench.so.signed",
    OE_ENCLAVE_TYPE_AUTO,
    OE_ENCLAVE_FLAG_DEBUG,
    NULL,
    0,
    &enclave);

  bool retval = false;
  int exit_code = run_benchmark(enclave, &retval) ? 0 : -1;
  if (!retval)
    exit_code = -1;

  return exit_code;
}