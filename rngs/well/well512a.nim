## Adapted from [Panneton](http://www.iro.umontreal.ca/~panneton/well/WELL512a.c)

import "../rngs"

const
  W = 32
  R = 16
  P = 0
  M1 = 13 ## first parameter of the algorithm
  M2 = 9 ## second parameter of the algorithm
  M3 = 5 ## third parameter of the algorithm

const Fact = 2.32830643653869628906e-10'f64

type
  Well512aObj = object of RandomNumberGeneratorObj
    state: array[R, int]
    i: int
    z0,z1,z2: int
  Well512a* = ref Well512aObj

proc mat0pos(t, v: int): int {.inline.} = v xor (v shr t)
proc mat0neg(t, v: int): int {.inline.} = v xor (v shl (-t))
proc mat3neg(t, v: int): int {.inline.} = v shl -t
proc mat4neg(t, b, v: int): int {.inline.} = v xor ((v shl (-t)) and b)

proc newWell512a*(init: openarray[int]): Well512a =
  assert(len(init) == 16)
  new(result)
  result.i = 0
  for j in 0..<R:
    result.state[j] = init[j]

proc well512a*(w: Well512a): float64 =
  w.z0 = w.state[(w.i+15) and 0x0000000f]
  w.z1 = mat0neg(-16,w.state[w.i]) xor
         mat0neg(-15,w.state[(w.i+M1) and 0x0000000f])
  w.z2 = mat0pos(11,w.state[(w.i+M2) and 0x0000000f])
  w.state[w.i] = w.z1 xor w.z2
  w.state[(w.i+15) and 0x0000000f] = mat0neg(-2,w.z0) xor
                                     mat0neg(-18,w.z1) xor
                                     mat3neg(-28,w.z2) xor
                                     mat4neg(-5,0xda442d24,w.state[w.i])
  w.i = (w.i + 15) and 0x0000000f
  result = float64(w.state[w.i]) * Fact
