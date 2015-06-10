## Based off [Spire](https://github.com/non/spire/random/rng)

import times
import "../rngs"

type
  Cmwc5Obj = object of RandomNumberGeneratorObj
    x,y,z,w,v: int64 ## state
  Cmwc5* = ref Cmwc5Obj

proc newCmwc5*(x,y,z,w,v: int64): Cmwc5 =
  new(result)
  result.x = x
  result.y = y
  result.z = z
  result.w = w
  result.v = v

proc newCmwc5*(): Cmwc5 =
  var (x,y,z,w,v) = (epochTime().int64,
                     epochTime().int64,
                     epochTime().int64,
                     epochTime().int64,
                     epochTime().int64)
  new(result)
  result.x = x
  result.y = y
  result.z = z
  result.w = w
  result.v = v


proc next*(c: Cmwc5): int64 =
  var t: int64 = c.x xor (c.x shr 7)
  c.x = c.y
  c.y = c.z
  c.z = c.w
  c.w = c.v
  c.v = (c.v xor (c.v shl 6)) xor (t xor (t shl 13))
  result = (c.y +% c.y +% 1) *% c.v

proc nextFloat*(c: Cmwc5): float =
  result = next(c).float / high(int64).float
