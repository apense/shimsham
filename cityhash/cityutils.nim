import unsigned

type uint128 = (uint64, uint64)

proc hash128to64(x: uint128): uint64 {.inline.} =
  ## Hash 128 input bits down to 64 bits of output
  ## Intended to be a reasonably god hash function
  # Murmur-inspired hashing
  const kMul = 0x9ddfea08eb382d69'u64
  var a: uint64 = (x[0] xor x[1]) * kMul
  a = a xor (a shr 47)
  var b: uint64 = (x[1] xor a) * kMul
  b = b xor (b shr 47)
  b = b * kMul
  result = b

proc bswap32(x: uint32): uint32 {.inline.} =
  result = ((((x) and 0xff000000u32) shr 24u32) or
            (((x) and 0x00ff0000u32) shr  8u32) or
            (((x) and 0x0000ff00u32) shl  8u32) or
            (((x) and 0x000000ffu32) shl 24u32))

proc bswap64(x: uint64): uint64 {.inline.} =
  result = ((((x) and 0xff00000000000000u64) shr 56u64) or
            (((x) and 0x00ff000000000000u64) shr 40u64) or
            (((x) and 0x0000ff0000000000u64) shr 24u64) or
            (((x) and 0x000000ff00000000u64) shr  8u64) or
            (((x) and 0x00000000ff000000u64) shr  8u64) or
            (((x) and 0x0000000000ff0000u64) shr 24u64) or
            (((x) and 0x000000000000ff00u64) shr 40u64) or
            (((x) and 0x00000000000000ffu64) shr 56u64))

when (cpuEndian == bigEndian):
  proc uint32InExpectedOrder(x: uint32): uint32 {.inline.} = bswap32(x)
  proc uint64InExpectedOrder(x: uint64): uint64 {.inline.} = bswap64(x)
else:
  proc uint32InExpectedOrder(x: uint32): uint32 {.inline.} = x
  proc uint64InExpectedOrder(x: uint64): uint64 {.inline.} = x

proc unalignedLoad64(p: cstring): uint64 =
  var p = p
  copyMem(addr result, addr p, sizeof(result))
proc unalignedLoad32(p: cstring): uint32 =
  var p = p
  copyMem(addr result, addr p, sizeof(result))

proc fetch64(p: cstring): uint64 =
  result = uint64InExpectedOrder(unalignedLoad64(p))
proc fetch32(p: cstring): uint32 =
  result = uint32InExpectedOrder(unalignedLoad32(p))
