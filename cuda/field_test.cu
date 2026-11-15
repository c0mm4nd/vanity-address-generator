// Test-only entry point. Python arbitrary-precision integers are the
// independent oracle; the device operations below are the exact production
// implementation.
#include "vanity.cu"

struct Arithmetic {
  F sum, difference, product, reciprocal, folded;
};
__global__ void arithmetic(const F *a, const F *b, Arithmetic *out,
                           uint32_t count) {
  uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i >= count)
    return;
  uint32_t wide[10];
  for (int j = 0; j < 8; j++)
    wide[j] = a[i].v[j];
  wide[8] = b[i].v[0];
  wide[9] = b[i].v[1];
  out[i] = {add(a[i], b[i]), sub(a[i], b[i]), mul(a[i], b[i]), inverse(a[i]),
            fold(wide)};
}
extern "C" int vag_cuda_test_fields(const F *a, const F *b, Arithmetic *out,
                                    uint32_t count) {
  if (!a || !b || !out || !count || count > 65536)
    return cudaErrorInvalidValue;
  F *da = nullptr, *db = nullptr;
  Arithmetic *dr = nullptr;
  auto run = [&]() -> cudaError_t {
    cudaError_t err;
    if ((err = cudaMalloc(&da, count * sizeof(F))))
      return err;
    if ((err = cudaMalloc(&db, count * sizeof(F))))
      return err;
    if ((err = cudaMalloc(&dr, count * sizeof(Arithmetic))))
      return err;
    if ((err = cudaMemcpy(da, a, count * sizeof(F), cudaMemcpyHostToDevice)))
      return err;
    if ((err = cudaMemcpy(db, b, count * sizeof(F), cudaMemcpyHostToDevice)))
      return err;
    arithmetic<<<(count + 127) / 128, 128>>>(da, db, dr, count);
    if ((err = cudaGetLastError()))
      return err;
    return cudaMemcpy(out, dr, count * sizeof(Arithmetic),
                      cudaMemcpyDeviceToHost);
  };
  cudaError_t result = run();
  cudaFree(da);
  cudaFree(db);
  cudaFree(dr);
  return result;
}
