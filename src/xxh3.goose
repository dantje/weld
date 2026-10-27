// XXH3, 64-bit, seed 0, default secret: xxHash 0.8's fastest hash, the one
// lld's --build-id=fast takes. Scalar, as xxHash's own fallback is: the long
// loop multiplies 32 by 32 bits only, which compilers keep fast without
// SIMD. Checked against libxxhash by test.py.
namespace xxh3;
import std;
import .elf;

let SECRET: u8[192] = [
    0xb8, 0xfe, 0x6c, 0x39, 0x23, 0xa4, 0x4b, 0xbe, 0x7c, 0x01, 0x81, 0x2c, 0xf7, 0x21, 0xad, 0x1c,
    0xde, 0xd4, 0x6d, 0xe9, 0x83, 0x90, 0x97, 0xdb, 0x72, 0x40, 0xa4, 0xa4, 0xb7, 0xb3, 0x67, 0x1f,
    0xcb, 0x79, 0xe6, 0x4e, 0xcc, 0xc0, 0xe5, 0x78, 0x82, 0x5a, 0xd0, 0x7d, 0xcc, 0xff, 0x72, 0x21,
    0xb8, 0x08, 0x46, 0x74, 0xf7, 0x43, 0x24, 0x8e, 0xe0, 0x35, 0x90, 0xe6, 0x81, 0x3a, 0x26, 0x4c,
    0x3c, 0x28, 0x52, 0xbb, 0x91, 0xc3, 0x00, 0xcb, 0x88, 0xd0, 0x65, 0x8b, 0x1b, 0x53, 0x2e, 0xa3,
    0x71, 0x64, 0x48, 0x97, 0xa2, 0x0d, 0xf9, 0x4e, 0x38, 0x19, 0xef, 0x46, 0xa9, 0xde, 0xac, 0xd8,
    0xa8, 0xfa, 0x76, 0x3f, 0xe3, 0x9c, 0x34, 0x3f, 0xf9, 0xdc, 0xbb, 0xc7, 0xc7, 0x0b, 0x4f, 0x1d,
    0x8a, 0x51, 0xe0, 0x4b, 0xcd, 0xb4, 0x59, 0x31, 0xc8, 0x9f, 0x7e, 0xc9, 0xd9, 0x78, 0x73, 0x64,
    0xea, 0xc5, 0xac, 0x83, 0x34, 0xd3, 0xeb, 0xc3, 0xc5, 0x81, 0xa0, 0xff, 0xfa, 0x13, 0x63, 0xeb,
    0x17, 0x0d, 0xdd, 0x51, 0xb7, 0xf0, 0xda, 0x49, 0xd3, 0x16, 0x55, 0x26, 0x29, 0xd4, 0x68, 0x9e,
    0x2b, 0x16, 0xbe, 0x58, 0x7d, 0x47, 0xa1, 0xfc, 0x8f, 0xf8, 0xb8, 0xd1, 0x7a, 0xd0, 0x31, 0xce,
    0x45, 0xcb, 0x3a, 0x8f, 0x95, 0x16, 0x04, 0x28, 0xaf, 0xd7, 0xfb, 0xca, 0xbb, 0x4b, 0x40, 0x7e,
];

let P32_1: u64 = 0x9e3779b1;
let P32_2: u64 = 0x85ebca77;
let P32_3: u64 = 0xc2b2ae3d;
let P64_1: u64 = 0x9e3779b185ebca87;
let P64_2: u64 = 0xc2b2ae3d27d4eb4f;
let P64_3: u64 = 0x165667b19e3779f9;
let P64_4: u64 = 0x85ebca77c2b2ae63;
let P64_5: u64 = 0x27d4eb2f165667c5;
let PMX_1: u64 = 0x165667919e3779f9;
let PMX_2: u64 = 0x9fb21c651e98df25;

inline fn rd64(b: const u8[:], at: i64) -> u64 { elf::u64le(b, at) }
inline fn rd32(b: const u8[:], at: i64) -> u64 { elf::u32le(b, at) }
inline fn rotl(x: u64, r: u64) -> u64 { (x << r) | (x >> (64 - r)) }
inline fn swap32(x: u64) -> u64 {
    ((x & 0xff) << 24) | ((x & 0xff00) << 8) | ((x >> 8) & 0xff00) | ((x >> 24) & 0xff)
}
inline fn swap64(x: u64) -> u64 { (swap32(x & 0xffffffff) << 32) | swap32(x >> 32) }

// The 128-bit product of a and b, its halves xored.
inline fn mul_fold(a: u64, b: u64) -> u64 {
    let a_lo = a & 0xffffffff;
    let a_hi = a >> 32;
    let b_lo = b & 0xffffffff;
    let b_hi = b >> 32;
    let lo_lo = a_lo * b_lo;
    let hi_lo = a_hi * b_lo;
    let lo_hi = a_lo * b_hi;
    let hi_hi = a_hi * b_hi;
    let cross = (lo_lo >> 32) + (hi_lo & 0xffffffff) + lo_hi;
    let upper = (hi_lo >> 32) + (cross >> 32) + hi_hi;
    let lower = (cross << 32) | (lo_lo & 0xffffffff);
    return lower ^ upper;
}

inline fn avalanche(h0: u64) -> u64 {
    var h = h0 ^ (h0 >> 37);
    h *= PMX_1;
    return h ^ (h >> 32);
}

inline fn avalanche64(h0: u64) -> u64 {
    var h = h0 ^ (h0 >> 33);
    h *= P64_2;
    h ^= h >> 29;
    h *= P64_3;
    return h ^ (h >> 32);
}

inline fn rrmxmx(h0: u64, len: u64) -> u64 {
    var h = h0 ^ rotl(h0, 49) ^ rotl(h0, 24);
    h *= PMX_2;
    h ^= (h >> 35) + len;
    h *= PMX_2;
    return h ^ (h >> 28);
}

inline fn mix16(b: const u8[:], at: i64, secret: const u8[:], s: i64) -> u64 {
    mul_fold(rd64(b, at) ^ rd64(secret, s), rd64(b, at + 8) ^ rd64(secret, s + 8))
}

// The 64-bit XXH3 of b.
fn hash(b: const u8[:]) -> u64 {
    let k = SECRET[..];
    let n = b.len;
    let len = n as! u64;
    if n <= 16 {
        if n > 8 {
            let lo = rd64(b, 0) ^ (rd64(k, 24) ^ rd64(k, 32));
            let hi = rd64(b, n - 8) ^ (rd64(k, 40) ^ rd64(k, 48));
            return avalanche(len + swap64(lo) + hi + mul_fold(lo, hi));
        }
        if n >= 4 {
            let x = rd32(b, n - 4) + (rd32(b, 0) << 32);
            return rrmxmx(x ^ (rd64(k, 8) ^ rd64(k, 16)), len);
        }
        if n > 0 {
            let c: u64 = (b[0] as u64 << 16) | (b[n >> 1] as u64 << 24) | b[n - 1] | (len << 8);
            return avalanche64(c ^ (rd32(k, 0) ^ rd32(k, 4)));
        }
        return avalanche64(rd64(k, 56) ^ rd64(k, 64));
    }
    if n <= 128 {
        var acc = len * P64_1;
        if n > 32 {
            if n > 64 {
                if n > 96 {
                    acc += mix16(b, 48, k, 96);
                    acc += mix16(b, n - 64, k, 112);
                }
                acc += mix16(b, 32, k, 64);
                acc += mix16(b, n - 48, k, 80);
            }
            acc += mix16(b, 16, k, 32);
            acc += mix16(b, n - 32, k, 48);
        }
        acc += mix16(b, 0, k, 0);
        acc += mix16(b, n - 16, k, 16);
        return avalanche(acc);
    }
    if n <= 240 {
        var acc = len * P64_1;
        for i in 8 { acc += mix16(b, 16 * i, k, 16 * i); }
        var tail = mix16(b, n - 16, k, 136 - 17);
        acc = avalanche(acc);
        for i in 8..n / 16 { tail += mix16(b, 16 * i, k, 16 * (i - 8) + 3); }
        return avalanche(acc + tail);
    }
    return long(b);
}

// The eight lanes of the long loop, as locals: no array behind a reference
// for the C compiler to keep in memory.
struct Lanes { a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64, a7: u64 }

// One lane pair's step: lane i takes the product of its keyed word's
// halves, its neighbour (i ^ 1) the word itself.
inline fn mul32(x: u64) -> u64 { (x & 0xffffffff) * (x >> 32) }

// 64 bytes at b[at..] into the lanes, keyed by the secret from s.
inline fn stripe(l: Lanes&, b: const u8[:], at: i64, k: const u8[:], s: i64) {
    let d = b[at..at + 64];                          // one check for the stripe, none for its words
    let key = k[s..s + 64];
    let v0 = rd64(d, 0);
    let v1 = rd64(d, 8);
    let v2 = rd64(d, 16);
    let v3 = rd64(d, 24);
    let v4 = rd64(d, 32);
    let v5 = rd64(d, 40);
    let v6 = rd64(d, 48);
    let v7 = rd64(d, 56);
    l.a0 += v1 + mul32(v0 ^ rd64(key, 0));
    l.a1 += v0 + mul32(v1 ^ rd64(key, 8));
    l.a2 += v3 + mul32(v2 ^ rd64(key, 16));
    l.a3 += v2 + mul32(v3 ^ rd64(key, 24));
    l.a4 += v5 + mul32(v4 ^ rd64(key, 32));
    l.a5 += v4 + mul32(v5 ^ rd64(key, 40));
    l.a6 += v7 + mul32(v6 ^ rd64(key, 48));
    l.a7 += v6 + mul32(v7 ^ rd64(key, 56));
}

inline fn scramble1(a: u64, k: const u8[:], at: i64) -> u64 { ((a ^ (a >> 47)) ^ rd64(k, at)) * P32_1 }

inline fn scramble(l: Lanes&, k: const u8[:]) {
    let key = k[192 - 64..];
    l.a0 = scramble1(l.a0, key, 0);
    l.a1 = scramble1(l.a1, key, 8);
    l.a2 = scramble1(l.a2, key, 16);
    l.a3 = scramble1(l.a3, key, 24);
    l.a4 = scramble1(l.a4, key, 32);
    l.a5 = scramble1(l.a5, key, 40);
    l.a6 = scramble1(l.a6, key, 48);
    l.a7 = scramble1(l.a7, key, 56);
}

fn long(b: const u8[:]) -> u64 {
    let k = SECRET[..];
    let n = b.len;
    var l = Lanes { a0: P32_3, a1: P64_1, a2: P64_2, a3: P64_3, a4: P64_4, a5: P32_2, a6: P64_5, a7: P32_1 };
    let per_block = (192 - 64) / 8;                  // 16 stripes a block
    let block_len = 64 * per_block;
    let blocks = (n - 1) / block_len;
    for j in blocks {
        for s in per_block { stripe(l, b, j * block_len + 64 * s, k, 8 * s); }
        scramble(l, k);
    }
    let stripes = ((n - 1) - block_len * blocks) / 64;
    for s in stripes { stripe(l, b, blocks * block_len + 64 * s, k, 8 * s); }
    stripe(l, b, n - 64, k, 192 - 64 - 7);
    let m = k[11..11 + 64];
    var h = (n as! u64) * P64_1;
    h += mul_fold(l.a0 ^ rd64(m, 0), l.a1 ^ rd64(m, 8));
    h += mul_fold(l.a2 ^ rd64(m, 16), l.a3 ^ rd64(m, 24));
    h += mul_fold(l.a4 ^ rd64(m, 32), l.a5 ^ rd64(m, 40));
    h += mul_fold(l.a6 ^ rd64(m, 48), l.a7 ^ rd64(m, 56));
    return avalanche(h);
}

// The build ID, as the output is written: every write adds its XXH3,
// mixed with where it goes and how long it is, to a sum, which each thread
// keeps for its own writes and reports. Sums commute, so the total is the
// same whichever thread writes what in whichever order; and since the file
// starts as zeros, the bytes no write covers are the same in every file of
// its size. on is false when no ID is to be computed.
struct IdSum { on: bool, a: u64, b: u64 }

fn add(s: IdSum&, at: i64, data: const u8[:]) {
    if !s.on { return; }
    let x = hash(data);
    let p = (at as! u64) * P64_1 ^ (data.len as! u64);
    s.a += avalanche(x ^ p);
    s.b += avalanche64(x + rotl(p, 29));
}

// n bytes of ID from the total of every thread's sums over a file of size
// bytes: an XXH3 for each 8 of them.
fn id(a: u64, b: u64, size: i64, n: i64) -> u8[>..] {
    var id: u8[>..] = [];
    var k: u64 = 0;
    while id.len < n {
        let words: u64[4] = [a, b, size as! u64, k];
        var buf: u8[32] = [0; 32];
        for w, i in words { for j in 8 { buf[8 * i + j] = (w >> (8 * j as! u64)) as! u8; } }
        let h = hash(buf[..]);
        for j in 8 { id.push((h >> (8 * j as! u64)) as! u8); }
        k++;
    }
    id.resize(n, 0);
    return id;
}
