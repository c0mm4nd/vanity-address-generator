#!/usr/bin/env python3
"""Compare the production CUDA field operations with Python big integers.
Deterministic inputs are test-only and are never used by wallet generation.
"""
import ctypes as c
from pathlib import Path
import random
import sys

class Field(c.Structure):
    _fields_ = [('v', c.c_uint32 * 8)]

    @classmethod
    def from_integer(cls, n):
        return cls((c.c_uint32 * 8)(*((n >> (32 * i)) & 0xffffffff for i in range(8))))

    def integer(self):
        return sum(word << (32 * i) for i, word in enumerate(self.v))

class Arithmetic(c.Structure):
    _fields_ = [(name, Field) for name in ['sum', 'difference', 'product', 'reciprocal', 'folded']]

p = 2**256 - 2**32 - 977
boundaries = [0, 1, 2, p - 1, p - 2, p - 977]
for bit in [32, 64, 96, 128, 160, 192, 224, 255]:
    boundaries += [2**bit - 1, 2**bit]
vectors = [(a, b) for a in boundaries for b in boundaries]
rng = random.Random(0x76616774657374)
vectors += [(rng.randrange(p), rng.randrange(p)) for _ in range(16384)]
count = len(vectors)
a = (Field * count)(*(Field.from_integer(a) for a, _ in vectors))
b = (Field * count)(*(Field.from_integer(b) for _, b in vectors))
out = (Arithmetic * count)()
library = c.CDLL(str(Path(sys.argv[1] if len(sys.argv) > 1 else 'target/release/libvag_cuda_test.so').resolve()))
library.vag_cuda_test_fields.argtypes = [c.POINTER(Field), c.POINTER(Field), c.POINTER(Arithmetic), c.c_uint32]
library.vag_cuda_test_fields.restype = c.c_int
library.vag_cuda_error.argtypes = [c.c_int]
library.vag_cuda_error.restype = c.c_char_p
status = library.vag_cuda_test_fields(a, b, out, count)
if status:
    raise RuntimeError(library.vag_cuda_error(status).decode())
for i, (a, b) in enumerate(vectors):
    expected = [(a+b) % p, (a-b) % p, (a*b) % p, pow(a, p-2, p) if a else 0,
                (a + ((b & (2**64 - 1)) << 256)) % p]
    for (name, _), expected_value in zip(Arithmetic._fields_, expected):
        actual = getattr(out[i], name).integer()
        assert actual == expected_value, f'{name} mismatch at vector {i}'
print(f'CUDA field arithmetic: {count} vectors x {len(Arithmetic._fields_)} operations match Python big integers')
