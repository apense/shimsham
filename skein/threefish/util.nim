# little-endian helper utilities

proc uint64le(b: openarray[byte], offset: int): uint64 {.noSideEffect.} =
  result = (b[0+offset].int shl  0).uint64 or
           (b[1+offset].int shl  8).uint64 or
           (b[2+offset].int shl 16).uint64 or
           (b[3+offset].int shl 24).uint64 or
           (b[4+offset].int shl 32).uint64 or
           (b[5+offset].int shl 40).uint64 or
           (b[6+offset].int shl 48).uint64 or
           (b[7+offset].int shl 56).uint64
proc putUint64le(b: var openarray[byte], offset: int, v: uint64) =
  b[0+offset] = byte(v)
  b[1+offset] = byte(v shr  8)
  b[2+offset] = byte(v shr 16)
  b[3+offset] = byte(v shr 24)
  b[4+offset] = byte(v shr 32)
  b[5+offset] = byte(v shr 40)
  b[6+offset] = byte(v shr 48)
  b[7+offset] = byte(v shr 56)
