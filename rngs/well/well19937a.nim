## Adapted from [Panneton](http://www.iro.umontreal.ca/~panneton/well/WELL19937a.c)

import "../rngs"
import unsigned

const
  W = 32
  R = 624
  P = 31
  Masku = 0xffffffff'u32 shr (W - P)
  Maskl = not Masku
  M1 = 70 ## first parameter of the algorithm
  M2 = 179 ## second parameter of the algorithm
  M3 = 449 ## third parameter of the algorithm

type
  Well19937aObj = object of RandomNumberGeneratorObj
    state: array[R, uint32]
    i: int
    z0,z1,z2: uint32
    rng: proc(w: Well19937a): float
  Well19937a* = ref Well19937aObj

const Fact = 2.32830643653869628906e-10'f64

const
  TemperB = 0xe46e1700'u32
  TemperC = 0x9b868000'u32


proc mat0pos(t: int, v: uint32): uint32 {.inline.} = v xor (v shr t.uint32)
proc mat0neg(t: int, v: uint32): uint32 {.inline.} = v xor (v shl uint32(-t))
proc mat1(v: uint32): uint32 {.inline.} = v
proc mat3pos(t: int, v: uint32): uint32 {.inline.} = v shr t.uint32
#proc mat3neg(t, v: int): int {.inline.} = v shl -t
#proc mat4neg(t, b, v: int): int {.inline.} = v xor ((v shl (-t)) and b)

template V0: uint32 = w.state[w.i]
template VM1Over: uint32 = w.state[(w.i + M1 - R)]
template VM1: uint32 = w.state[(w.i+M1)]
template VM2Over: uint32 = w.state[(w.i + M2 - R)]
template VM2: uint32 = w.state[(w.i+M2)]
template VM3Over: uint32 = w.state[(w.i + M3 - R)]
template VM3: uint32 = w.state[(w.i+M3)]
template VRm1: uint32 = w.state[(w.i - 1)]
template VRm1Under: uint32 = w.state[w.i + R - 1]
template VRm2: uint32 = w.state[w.i - 2]
template VRm2Under: uint32 = w.state[w.i + R - 2]

template newV0: expr = w.state[(w.i - 1)]
template newV0Under: expr = w.state[(w.i - 1 + R)]
template newV1: expr = w.state[w.i]
template newVRm1: expr = w.state[w.i - 2]
template newVRm1Under: expr = w.state[w.i - 2 + R]

# forward declarations
proc case1(w: Well19937a): float
proc case2(w: Well19937a): float
proc case3(w: Well19937a): float
proc case4(w: Well19937a): float
proc case5(w: Well19937a): float
proc case6(w: Well19937a): float

proc case1(w: Well19937a): float =
  w.z0 = (VRm1Under and Maskl) or (VRm2Under and Masku)
  w.z1 = mat0neg(-25,V0) xor mat0pos(27,VM1)
  w.z2 = mat3pos( 9,VM2) xor mat0pos( 1,VM3)
  newV1 = w.z1 xor w.z2
  newV0Under = mat1(w.z0) xor mat0neg(-9, w.z1) xor mat0neg(-21, w.z2) xor mat0pos(21, newV1)
  w.i = R - 1
  w.rng = case3
  when defined(Tempering):
    var y: uint32
    y = w.state[w.i] xor ((w.state[w.i] shl 7) and TemperB)
    y =            y xor ((           y shl 15) and TemperC)
    result = y.float * Fact
  else:
    result = w.state[w.i].float * Fact

proc case2(w: Well19937a): float =
  w.z0 = (VRm1 and Maskl) or (VRm2Under and Masku)
  w.z1 = mat0neg(-25, V0) xor mat0pos(27, VM1)
  w.z2 = mat3pos( 9, VM2) xor mat0pos(1, VM3)
  newV1 = w.z1 xor w.z2
  newV0 = mat1(w.z0) xor mat0neg(-9, w.z1) xor
          mat0neg(-21, w.z2) xor mat0pos(21, newV1)
  w.i = 0
  w.rng = case1
  when defined(Tempering):
    var y: uint32
    y = w.state[w.i] xor ((w.state[w.i] shl 7) and TemperB)
    y =            y xor ((           y shl 15) and TemperC)
    result = y.float * Fact
  else:
    result = w.state[w.i].float * Fact

proc case3(w: Well19937a): float =
  w.z0 = (VRm1 and Maskl) or (VRm2 and Masku)
  w.z1 = mat0neg(-25, V0) xor mat0pos(27, VM1Over)
  w.z2 = mat3pos( 9, VM2Over) xor mat0pos(1, VM3Over)
  newV1 = w.z1 xor w.z2
  newV0 = mat1(w.z0) xor mat0neg(-9, w.z1) xor
          mat0neg(-21, w.z2) xor mat0pos(21, newV1)
  dec w.i
  if (w.i + M1) < R:
    w.rng = case5
  when defined(Tempering):
    var y: uint32
    y = w.state[w.i] xor ((w.state[w.i] shl 7) and TemperB)
    y =            y xor ((           y shl 15) and TemperC)
    result = y.float * Fact
  else:
    result = w.state[w.i].float * Fact

proc case4(w: Well19937a): float =
  w.z0 = (VRm1 and Maskl) or (VRm2 and Masku)
  w.z1 = mat0neg(-25, V0) xor mat0pos(27, VM1)
  w.z2 = mat3pos( 9, VM2) xor mat0pos(1, VM3Over)
  newV1 = w.z1 xor w.z2
  newV0 = mat1(w.z0) xor mat0neg(-9, w.z1) xor
          mat0neg(-21, w.z2) xor mat0pos(21, newV1)
  dec w.i
  if (w.i + M3) < R:
    w.rng = case6
  when defined(Tempering):
    var y: uint32
    y = w.state[w.i] xor ((w.state[w.i] shl 7) and TemperB)
    y =            y xor ((           y shl 15) and TemperC)
    result = y.float * Fact
  else:
    result = w.state[w.i].float * Fact

proc case5(w: Well19937a): float =
  w.z0 = (VRm1 and Maskl) or (VRm2 and Masku)
  w.z1 = mat0neg(-25, V0) xor mat0pos(27, VM1)
  w.z2 = mat3pos( 9, VM2Over) xor mat0pos(1, VM3Over)
  newV1 = w.z1 xor w.z2
  newV0 = mat1(w.z0) xor mat0neg(-9, w.z1) xor
          mat0neg(-21, w.z2) xor mat0pos(21, newV1)
  dec w.i
  if (w.i + M2) < R:
    w.rng = case4
  when defined(Tempering):
    var y: uint32
    y = w.state[w.i] xor ((w.state[w.i] shl 7) and TemperB)
    y =            y xor ((           y shl 15) and TemperC)
    result = y.float * Fact
  else:
    result = w.state[w.i].float * Fact

proc case6(w: Well19937a): float =
  w.z0 = (VRm1 and Maskl) or (VRm2 and Masku)
  w.z1 = mat0neg(-25, V0) xor mat0pos(27, VM1)
  w.z2 = mat3pos( 9, VM2) xor mat0pos(1, VM3)
  newV1 = w.z1 xor w.z2
  newV0 = mat1(w.z0) xor mat0neg(-9, w.z1) xor
          mat0neg(-21, w.z2) xor mat0pos(21, newV1)
  dec w.i
  if w.i == 1:
    w.rng = case2
  when defined(Tempering):
    var y: uint32
    y = w.state[w.i] xor ((w.state[w.i] shl 7) and TemperB)
    y =            y xor ((           y shl 15) and TemperC)
    result = y.float * Fact
  else:
    result = w.state[w.i].float * Fact

proc newWell19937a*(init: openarray[uint32]): Well19937a =
  assert(len(init) == R)
  new(result)
  result.i = 0
  result.rng = case1
  for j in 0..<R:
    result.state[j] = init[j]
