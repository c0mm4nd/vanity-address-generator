// secp256k1 affine batch addition + Ethereum Keccak-256.
// Private scalars stay on the host; device input consists only of public
// points.
#include <cuda_runtime.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

constexpr int BATCH = 128;
// Canonical field elements modulo p = 2^256 - 2^32 - 977, little-endian limbs.
struct F {
  uint32_t v[8];
};
struct Point {
  F x, y;
};
struct Hit {
  uint32_t lane, step;
  uint8_t hash[20];
};
struct Filter {
  uint8_t value[20], mask[20];
};
struct BatchStats {
  uint32_t hits, processed;
  float kernel_ms;
};
static_assert(sizeof(Point) == 64 && sizeof(Hit) == 28 &&
                  sizeof(BatchStats) == 12,
              "Rust/CUDA ABI layout mismatch");
__constant__ Point table[BATCH];
__device__ __forceinline__ uint32_t prime(int i) {
  return i == 0 ? 0xfffffc2fU : (i == 1 ? 0xfffffffeU : 0xffffffffU);
}
__device__ __forceinline__ bool zero(F a) {
  uint32_t v = 0;
  for (int i = 0; i < 8; i++)
    v |= a.v[i];
  return v == 0;
}
__device__ __forceinline__ bool equal(F a, F b) {
  uint32_t v = 0;
  for (int i = 0; i < 8; i++)
    v |= a.v[i] ^ b.v[i];
  return v == 0;
}
__device__ __forceinline__ F normalize(F a) {
  bool ge = true;
  for (int i = 7; i >= 0; i--) {
    if (a.v[i] != prime(i)) {
      ge = a.v[i] > prime(i);
      break;
    }
  }
  if (ge) {
    uint64_t borrow = 0;
    for (int i = 0; i < 8; i++) {
      uint64_t s = (uint64_t)prime(i) + borrow;
      uint32_t old = a.v[i];
      a.v[i] = (uint32_t)((uint64_t)old - s);
      borrow = (uint64_t)old < s;
    }
  }
  return a;
}
__device__ __forceinline__ F fold(uint32_t r[10]) {
  // Each overflow limb folds back using 2^256 == 2^32 + 977 (mod p).
  while (r[8] || r[9]) {
    uint32_t h = r[8], h2 = r[9];
    r[8] = r[9] = 0;
    uint64_t c = 0;
    for (int i = 0; i < 10; i++) {
      uint64_t extra = i == 0   ? (uint64_t)h * 977
                       : i == 1 ? (uint64_t)h + (uint64_t)h2 * 977
                       : i == 2 ? h2
                                : 0;
      uint64_t z = (uint64_t)r[i] + extra + c;
      r[i] = (uint32_t)z;
      c = z >> 32;
    }
  }
  F a;
  for (int i = 0; i < 8; i++)
    a.v[i] = r[i];
  return normalize(a);
}
__device__ __forceinline__ F add(F a, F b) {
  uint32_t r[10] = {};
  uint64_t c = 0;
  for (int i = 0; i < 8; i++) {
    uint64_t z = (uint64_t)a.v[i] + b.v[i] + c;
    r[i] = (uint32_t)z;
    c = z >> 32;
  }
  r[8] = (uint32_t)c;
  return fold(r);
}
__device__ __forceinline__ F sub(F a, F b) {
  F r;
  uint64_t borrow = 0;
  for (int i = 0; i < 8; i++) {
    uint64_t s = (uint64_t)b.v[i] + borrow;
    r.v[i] = (uint32_t)((uint64_t)a.v[i] - s);
    borrow = (uint64_t)a.v[i] < s;
  }
  if (borrow) {
    uint64_t c = 0;
    for (int i = 0; i < 8; i++) {
      uint64_t z = (uint64_t)r.v[i] + prime(i) + c;
      r.v[i] = (uint32_t)z;
      c = z >> 32;
    }
  }
  return r;
}
__device__ __forceinline__ F mul(F a, F b) {
  uint32_t t[16] = {};
  for (int i = 0; i < 8; i++) {
    uint64_t c = 0;
    for (int j = 0; j < 8; j++) {
      uint64_t z = (uint64_t)a.v[i] * b.v[j] + t[i + j] + c;
      t[i + j] = (uint32_t)z;
      c = z >> 32;
    }
    t[i + 8] = (uint32_t)c;
  }
  uint32_t r[10];
  uint64_t c = 0;
  for (int i = 0; i < 8; i++) {
    uint64_t z =
        (uint64_t)t[i] + (uint64_t)t[i + 8] * 977 + (i ? t[i + 7] : 0) + c;
    r[i] = (uint32_t)z;
    c = z >> 32;
  }
  uint64_t z = (uint64_t)t[15] + c;
  r[8] = (uint32_t)z;
  r[9] = (uint32_t)(z >> 32);
  return fold(r);
}
__device__ __forceinline__ F square_n(F r, int n) {
  // Keep long chains rolled: unrolling every field multiplication inflates code.
#pragma unroll 1
  for (int i = 0; i < n; i++)
    r = mul(r, r);
  return r;
}
__device__ F inverse(F a) {
  // Addition chain for p-2: 255 squares and 15 other multiplications.
  // xn = a^(2^n-1). Zero stays zero, as in the binary exponentiation version.
  F x2 = mul(square_n(a, 1), a);
  F x3 = mul(square_n(x2, 1), a);
  F x6 = mul(square_n(x3, 3), x3);
  F x9 = mul(square_n(x6, 3), x3);
  F x11 = mul(square_n(x9, 2), x2);
  F x22 = mul(square_n(x11, 11), x11);
  F x44 = mul(square_n(x22, 22), x22);
  F x88 = mul(square_n(x44, 44), x44);
  F x176 = mul(square_n(x88, 88), x88);
  F x220 = mul(square_n(x176, 44), x44);
  F x223 = mul(square_n(x220, 3), x3);
  F r = mul(square_n(x223, 23), x22); // 2^246 - 2^22 - 1
  r = mul(square_n(r, 5), a);        // 2^251 - 2^27 - 31
  r = mul(square_n(r, 3), x2);       // 2^254 - 2^30 - 245
  return mul(square_n(r, 2), a);     // 2^256 - 2^32 - 979 = p-2
}
__device__ bool infinity(Point p) { return zero(p.x) && zero(p.y); }
__device__ Point sum_with_inverse(Point a, Point b, F inv) {
  F slope = mul(sub(b.y, a.y), inv);
  F x = sub(sub(mul(slope, slope), a.x), b.x);
  return {x, sub(mul(slope, sub(a.x, x)), a.y)};
}
__device__ Point exceptional_sum(Point a, Point b) {
  if (infinity(a))
    return b;
  if (!equal(a.y, b.y) || zero(a.y))
    return {};
  F xx = mul(a.x, a.x);
  F slope = mul(add(add(xx, xx), xx), inverse(add(a.y, a.y)));
  F x = sub(sub(mul(slope, slope), a.x), a.x);
  return {x, sub(mul(slope, sub(a.x, x)), a.y)};
}

__device__ __forceinline__ uint64_t rot(uint64_t x, int n) {
  return n ? (x << n) | (x >> (64 - n)) : x;
}
__device__ void address_hash(Point p, uint8_t out[20]) {
  const uint64_t rc[24] = {0x1ULL,
                           0x8082ULL,
                           0x800000000000808aULL,
                           0x8000000080008000ULL,
                           0x808bULL,
                           0x80000001ULL,
                           0x8000000080008081ULL,
                           0x8000000000008009ULL,
                           0x8aULL,
                           0x88ULL,
                           0x80008009ULL,
                           0x8000000aULL,
                           0x8000808bULL,
                           0x800000000000008bULL,
                           0x8000000000008089ULL,
                           0x8000000000008003ULL,
                           0x8000000000008002ULL,
                           0x8000000000000080ULL,
                           0x800aULL,
                           0x800000008000000aULL,
                           0x8000000080008081ULL,
                           0x8000000000008080ULL,
                           0x80000001ULL,
                           0x8000000080008008ULL};
  const int rotation[25] = {0,  1,  62, 28, 27, 36, 44, 6,  55, 20, 3,  10, 43,
                            25, 39, 41, 45, 15, 21, 8,  18, 2,  61, 56, 14};
  uint64_t s[25] = {};
  // Convert the big-endian public coordinates into Keccak's little-endian
  // lanes directly, instead of packing 64 individual bytes.
#pragma unroll
  for (int i = 0; i < 4; i++) {
    s[i] = (uint64_t)__byte_perm(p.x.v[7 - 2 * i], 0, 0x0123) |
           ((uint64_t)__byte_perm(p.x.v[6 - 2 * i], 0, 0x0123) << 32);
    s[i + 4] = (uint64_t)__byte_perm(p.y.v[7 - 2 * i], 0, 0x0123) |
               ((uint64_t)__byte_perm(p.y.v[6 - 2 * i], 0, 0x0123) << 32);
  }
  s[8] = 1;
  s[16] = 0x8000000000000000ULL; // Keccak (not SHA3) padding, rate 136.
#pragma unroll 24
  for (int round = 0; round < 24; round++) {
    uint64_t c[5], d[5], b[25];
#pragma unroll
    for (int x = 0; x < 5; x++)
      c[x] = s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20];
#pragma unroll
    for (int x = 0; x < 5; x++)
      d[x] = c[(x + 4) % 5] ^ rot(c[(x + 1) % 5], 1);
#pragma unroll
    for (int y = 0; y < 5; y++)
#pragma unroll
      for (int x = 0; x < 5; x++)
        b[y + 5 * ((2 * x + 3 * y) % 5)] =
            rot(s[x + 5 * y] ^ d[x], rotation[x + 5 * y]);
#pragma unroll
    for (int y = 0; y < 5; y++)
#pragma unroll
      for (int x = 0; x < 5; x++)
        s[x + 5 * y] =
            b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
    s[0] ^= rc[round];
  }
#pragma unroll
  for (int i = 0; i < 20; i++)
    out[i] = (uint8_t)(s[(i + 12) / 8] >> (8 * ((i + 12) % 8)));
}

// The public API still accepts P and returns P+G through P+128G. Internally,
// keep C=P+64G so that C+jG and C-jG share the same x-coordinate denominator.
__global__ void center_seeds(Point *points, uint32_t lanes) {
  uint32_t lane = blockIdx.x * blockDim.x + threadIdx.x;
  if (lane >= lanes)
    return;
  Point p = points[lane], shift = table[BATCH / 2 - 1];
  F dx = sub(shift.x, p.x);
  points[lane] = (infinity(p) || zero(dx))
                    ? exceptional_sum(p, shift)
                    : sum_with_inverse(p, shift, inverse(dx));
}
__device__ __forceinline__ uint32_t emit(Point q, uint32_t lane, uint32_t step,
                                        Hit *hits, uint32_t *count, Filter filter) {
  if (infinity(q))
    return 0;
  uint8_t hash[20];
  address_hash(q, hash);
  bool match = true;
  for (int j = 0; j < 20; j++)
    if ((hash[j] & filter.mask[j]) != filter.value[j])
      match = false;
  if (match) {
    uint32_t slot = atomicAdd(count, 1U);
    hits[slot].lane = lane;
    hits[slot].step = step;
    for (int j = 0; j < 20; j++)
      hits[slot].hash[j] = hash[j];
  }
  return 1;
}
__global__ void scan(Point *points, uint32_t lanes, Hit *hits, uint32_t *count,
                     Filter filter) {
  uint32_t lane = blockIdx.x * blockDim.x + threadIdx.x;
  if (lane >= lanes)
    return;
  constexpr int HALF = BATCH / 2;
  Point center = points[lane];
  // 64 paired denominators plus one for advancing the center by 128G.
  F products[HALF + 1];
  F acc = {};
  acc.v[0] = 1;
  for (int i = 0; i <= HALF; i++) {
    products[i] = acc;
    F dx = sub(table[i == HALF ? BATCH - 1 : i].x, center.x);
    if (!zero(dx))
      acc = mul(acc, dx);
  }
  acc = inverse(acc);
  uint32_t processed = 0;
  Point next = {};
  for (int i = HALF; i >= 0; i--) {
    Point delta = table[i == HALF ? BATCH - 1 : i];
    F dx = sub(delta.x, center.x);
    bool exceptional = infinity(center) || zero(dx);
    F inv = {};
    if (!zero(dx)) {
      inv = mul(acc, products[i]);
      acc = mul(acc, dx);
    }
    int phases = i >= HALF - 1 ? 1 : 2;
    // Reuse one hash body for both signs. Unrolling this loop increases code
    // size and the number of live temporaries across the Keccak calculation.
#pragma unroll 1
    for (int sign = 0; sign < phases; sign++) {
      if (sign)
        delta.y = sub(F{}, delta.y);
      Point q = exceptional ? exceptional_sum(center, delta)
                            : sum_with_inverse(center, delta, inv);
      uint32_t step = sign ? HALF - i - 1 : HALF + i + 1;
      if (i == HALF) {
        // The extra denominator advances the center, without exporting it.
        // Export the current center itself as candidate 64 instead.
        next = q;
        q = center;
        step = HALF;
      }
      processed += emit(q, lane, step, hits, count, filter);
    }
  }
  points[lane] = next;
  atomicAdd(count + 1, processed);
}
struct Engine {
  Point *points;
  Hit *hits;
  uint32_t *count;
  uint32_t lanes;
  int device;
  Filter filter;
  cudaEvent_t start, stop;
};
extern "C" uint32_t vag_cuda_abi_version() { return 2; }
extern "C" const char *vag_cuda_error(int code) {
  return cudaGetErrorString((cudaError_t)code);
}
extern "C" int vag_cuda_destroy(Engine *e) {
  if (!e)
    return 0;
  cudaSetDevice(e->device);
  cudaFree(e->points);
  cudaFree(e->hits);
  cudaFree(e->count);
  if (e->start)
    cudaEventDestroy(e->start);
  if (e->stop)
    cudaEventDestroy(e->stop);
  free(e);
  return 0;
}
extern "C" int vag_cuda_create(int device, uint32_t lanes,
                               const Point *host_table, const uint8_t *value,
                               const uint8_t *mask, Engine **out) {
  *out = nullptr;
  if (!lanes || lanes > 65536)
    return cudaErrorInvalidValue;
  cudaError_t err = cudaSetDevice(device);
  if (err)
    return err;
  Engine *e = (Engine *)calloc(1, sizeof(Engine));
  if (!e)
    return cudaErrorMemoryAllocation;
  e->lanes = lanes;
  e->device = device;
  memcpy(e->filter.value, value, 20);
  memcpy(e->filter.mask, mask, 20);
  if (!(err = cudaMalloc(&e->points, lanes * sizeof(Point))) &&
      !(err = cudaMalloc(&e->hits, (size_t)lanes * BATCH * sizeof(Hit))) &&
      !(err = cudaMalloc(&e->count, 2 * sizeof(uint32_t))) &&
      !(err = cudaMemcpyToSymbol(table, host_table, BATCH * sizeof(Point))) &&
      !(err = cudaEventCreate(&e->start)))
    err = cudaEventCreate(&e->stop);
  if (err) {
    vag_cuda_destroy(e);
    return err;
  }
  *out = e;
  return 0;
}
extern "C" int vag_cuda_seed(Engine *e, const Point *points) {
  cudaError_t err = cudaSetDevice(e->device);
  if (err)
    return err;
  if ((err = cudaMemcpy(e->points, points, e->lanes * sizeof(Point),
                         cudaMemcpyHostToDevice)))
    return err;
  center_seeds<<<(e->lanes + 127) / 128, 128>>>(e->points, e->lanes);
  if ((err = cudaGetLastError()))
    return err;
  return cudaDeviceSynchronize();
}
extern "C" int vag_cuda_scan(Engine *e, Hit *hits, uint32_t capacity,
                             BatchStats *stats) {
  // Refuse undersized host buffers BEFORE launching or copying any results.
  if (!stats || !hits || capacity < e->lanes * BATCH)
    return cudaErrorInvalidValue;
  *stats = {};
  cudaError_t err = cudaSetDevice(e->device);
  if (err)
    return err;
  err = cudaMemset(e->count, 0, 2 * sizeof(uint32_t));
  if (err)
    return err;
  if ((err = cudaEventRecord(e->start)))
    return err;
  scan<<<(e->lanes + 127) / 128, 128>>>(e->points, e->lanes, e->hits, e->count,
                                        e->filter);
  if ((err = cudaGetLastError()))
    return err;
  if ((err = cudaEventRecord(e->stop)))
    return err;
  uint32_t counts[2];
  if ((err = cudaMemcpy(counts, e->count, sizeof(counts),
                        cudaMemcpyDeviceToHost)))
    return err;
  if (counts[0] > capacity || counts[1] > e->lanes * BATCH ||
      counts[0] > counts[1])
    return cudaErrorInvalidValue;
  stats->hits = counts[0];
  stats->processed = counts[1];
  if ((err = cudaEventElapsedTime(&stats->kernel_ms, e->start, e->stop)))
    return err;
  if (stats->hits)
    return cudaMemcpy(hits, e->hits, (size_t)stats->hits * sizeof(Hit),
                      cudaMemcpyDeviceToHost);
  return 0;
}
