## Based off [BurtleBurtle](http://burtleburtle.net/bob/rand/smallprng.html)
## Code in public domain

import times
import unsigned
import "../rngs"

type
  BurtleRotObj2 = object of RandomNumberGeneratorObj
    a,b,c,d: uint32 ## state
  BurtleRotObj3 = object of RandomNumberGeneratorObj
    a,b,c,d: uint32 ## state
  BurtleRotObj64 = object of RandomNumberGeneratorObj
    a,b,c,d: uint64 ## state
  BurtleRot2* = ref BurtleRotObj2
  BurtleRot3* = ref BurtleRotObj3
  BurtleRot64* = ref BurtleRotObj64

proc rot(x,k: uint32): uint32 {.inline.} = (x shl k) or (x shr (32u32 - k))
proc rot64(x,k: uint64): uint64 {.inline.} = (x shl k) or (x shr (64u64 - k))

proc next*(b: BurtleRot2): uint32 =
  var e = (b.a - rot(b.b, 27))
  b.a = (b.b xor rot(b.c, 17))
  b.b = (b.c + rot(b.d, 11))
  b.c = (b.d + e)
  b.d = (e + b.a)
  result = (b.d)

proc next*(b: BurtleRot64): uint64 =
  var e: uint64 = b.a - rot64(b.b, 7)
  b.a = (b.b xor rot64(b.c, 13))
  b.b = (b.c + rot64(b.d, 37))
  b.c = (b.d + e)
  b.d = (e + b.a)
  result = (b.d)

proc next*(b: BurtleRot3): uint32 =
  var e = (b.a - rot(b.b, 27))
  b.a = (b.b xor rot(b.c, 17))
  b.b = (b.c + b.d)
  b.c = (b.d + e)
  b.d = (e + b.a)
  result = (b.d)

proc nextFloat*(b: BurtleRot2): float =
  result = next(b).int / high(uint32).int

proc nextFloat*(b: BurtleRot3): float =
  result = next(b).int / high(uint32).int

proc nextFloat*(b: BurtleRot64): float =
  # since there is no high(uint64) in Nim, we improvise:
  #
  # high(int64) = pow(2,63) - 1
  # 2 * high(int64) = pow(2,64) - 2
  # high(uint64) = pow(2,64) - 1
  # so high(uint64) = 2 * high(int64) + 1
  #
  # but since we want to avoid overflows, what we'll actually do is use floating
  # point arithmetic to do all of this. it's less perfect, but it's easier
  let high64 = 18_446_744_073_709_551_615.0 # the float representation of pow(2,64) - 1
  var bval = next(b).float
  result = bval / high64

proc newBurtleRot2*(seed: uint32): BurtleRot2 =
  new(result)
  result.a = 0xf1ea5eed'u32
  result.b = seed
  result.c = seed
  result.d = seed

proc newBurtleRot3*(seed: uint32): BurtleRot3 =
  new(result)
  result.a = 0xf1ea5eed'u32
  result.b = seed
  result.c = seed
  result.d = seed

proc newBurtleRot64*(seed: uint64): BurtleRot64 =
  new(result)
  result.a = 0xf1ea5eed'u64
  result.b = seed
  result.c = seed
  result.d = seed

proc newBurtleRot2*(): BurtleRot2 =
  let seed = uint32(epochTime())
  new(result)
  result.a = 0xf1ea5eed'u32
  result.b = seed
  result.c = seed
  result.d = seed

proc newBurtleRot3*(): BurtleRot3 =
  let seed = uint32(epochTime())
  new(result)
  result.a = 0xf1ea5eed'u32
  result.b = seed
  result.c = seed
  result.d = seed

proc newBurtleRot64*(): BurtleRot64 =
  let seed = uint64(epochTime())
  new(result)
  result.a = 0xf1ea5eed'u64
  result.b = seed
  result.c = seed
  result.d = seed

proc newBurtleRot2*(seed: openarray[uint32]): BurtleRot2 =
  assert len(seed) == 4
  new(result)
  result.a = seed[0]
  result.b = seed[1]
  result.c = seed[2]
  result.d = seed[3]

proc newBurtleRot3*(seed: openarray[uint32]): BurtleRot3 =
  assert len(seed) == 4
  new(result)
  result.a = seed[0]
  result.b = seed[1]
  result.c = seed[2]
  result.d = seed[3]

proc newBurtleRot64*(seed: openarray[uint64]): BurtleRot64 =
  assert len(seed) == 4
  new(result)
  result.a = seed[0]
  result.b = seed[1]
  result.c = seed[2]
  result.d = seed[3]
