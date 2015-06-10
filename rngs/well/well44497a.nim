import "../rngs"
import unsigned

const
  W = 32
  R = 1391
  P = 15
  Masku = 0xffffffff'u32 shr (W - P)
  Maskl = not Masku
  M1 = 23 ## first parameter of the algorithm
  M2 = 481 ## second parameter of the algorithm
  M3 = 229 ## third parameter of the algorithm

type
  Well44497aObj = object of RandomNumberGeneratorObj
    state: array[R, uint32]
    i: int
    z0,z1,z2: uint32
    rng: proc(w: Well44497a): float
  Well44497a* = ref Well44497aObj

const Fact = 2.32830643653869628906e-10'f64

const
  TemperB = 0x93dd1400'u32
  TemperC = 0xfa118000'u32


proc mat0pos(t: int, v: uint32): uint32 {.inline.} = v xor (v shr t.uint32)
proc mat0neg(t: int, v: uint32): uint32 {.inline.} = v xor (v shl uint32(-t))
proc mat1(v: uint32): uint32 {.inline.} = v
proc mat2(a: int, v: uint32): uint32 {.inline.} = 
  if ((v and 1) != 0): 
    ((v shr 1) xor a.uint32) 
  else: (v shr 1)
proc mat3pos(t: int, v: uint32): uint32 {.inline.} = v shr t.uint32
proc mat3neg(t: int, v: uint32): uint32 {.inline.} = v shl uint32(-t)
proc mat4pos(t: int, b, v: uint32): uint32 {.inline.} = (v xor ((v shr t.uint32) and b))
proc mat4neg(t: int, b, v: uint32): uint32 {.inline.} = v xor ((v shl uint32(-t)) and b)
proc mat5(r: int,a,ds,dt,v: uint32): uint32 {.inline.} =
  if (v and dt) != 0:
    ((((v shl r.uint32) xor (v shr uint32(W - r))) and ds) xor a)
  else:
    (((v shl r.uint32) xor (v shr uint32(W - r))) and ds)
proc mat7(v: int): uint32 {.inline.} = 0

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
proc case1(w: Well44497a): float
proc case2(w: Well44497a): float
proc case3(w: Well44497a): float
proc case4(w: Well44497a): float
proc case5(w: Well44497a): float
proc case6(w: Well44497a): float

proc case1(w: Well44497a): float =
  w.z0 = (VRm1Under and Maskl) or (VRm2Under and Masku)
  w.z1 = mat0neg(-24,V0) xor mat0pos(30,VM1)
  w.z2 = mat3pos(-10,VM2) xor mat0pos(-26,VM3)
  newV1 = w.z1 xor w.z2
  newV0Under = mat1(w.z0) xor 
               mat0pos(20, w.z1) xor 
               mat5(9,0xb729fcec'u32,0xfbfffff'u32,0x00020000'u32,w.z2) xor 
               mat1(newV1)
  w.i = R - 1
  w.rng = case3
  when defined(Tempering):
    var y: uint32
    y = w.state[w.i] xor ((w.state[w.i] shl 7) and TemperB)
    y =            y xor ((           y shl 15) and TemperC)
    result = y.float * Fact
  else:
    result = w.state[w.i].float * Fact

proc case2(w: Well44497a): float =
  w.z0 = (VRm1 and Maskl) or (VRm2Under and Masku)
  w.z1 = mat0neg(-24, V0) xor mat0pos(30, VM1)
  w.z2 = mat0neg(-10, VM2) xor mat3neg(-26, VM3)
  newV1 = w.z1 xor w.z2
  newV0 = mat1(w.z0) xor 
          mat0pos(-9, w.z1) xor 
          mat5(9,0xb729fcec'u32,0xfbffffff'u32,0x00020000'u32,w.z2) xor 
          mat1(newV1)
  w.i = 0
  w.rng = case1
  when defined(Tempering):
    var y: uint32
    y = w.state[w.i] xor ((w.state[w.i] shl 7) and TemperB)
    y =            y xor ((           y shl 15) and TemperC)
    result = y.float * Fact
  else:
    result = w.state[w.i].float * Fact

proc case3(w: Well44497a): float =
  w.z0 = (VRm1 and Maskl) or (VRm2 and Masku)
  w.z1 = mat0neg(-24, V0) xor mat0pos(30, VM1Over)
  w.z2 = mat0neg(-10, VM2Over) xor mat3neg(-26, VM3Over)
  newV1 = w.z1 xor w.z2
  newV0 = mat1(w.z0) xor 
          mat0pos(20, w.z1) xor 
          mat5(9,0xb729fcec'u32,0xfbffffff'u32,0x00020000'u32,w.z2) xor 
          mat1(newV1)
  dec w.i
  if (w.i + M1) < R:
    w.rng = case4
  when defined(Tempering):
    var y: uint32
    y = w.state[w.i] xor ((w.state[w.i] shl 7) and TemperB)
    y =            y xor ((           y shl 15) and TemperC)
    result = y.float * Fact
  else:
    result = w.state[w.i].float * Fact

proc case4(w: Well44497a): float =
  w.z0 = (VRm1 and Maskl) or (VRm2 and Masku)
  w.z1 = mat0neg(-24, V0) xor mat0pos(30, VM1)
  w.z2 = mat0neg(-10, VM2Over) xor mat3neg(-26, VM3Over)
  newV1 = w.z1 xor w.z2
  newV0 = mat1(w.z0) xor 
          mat0pos(20, w.z1) xor 
          mat5(9,0xb729fcec'u32,0xfbffffff'u32,0x00020000'u32,w.z2) xor 
          mat1(newV1)
  dec w.i
  if (w.i + M3) < R:
    w.rng = case5
  when defined(Tempering):
    var y: uint32
    y = w.state[w.i] xor ((w.state[w.i] shl 7) and TemperB)
    y =            y xor ((           y shl 15) and TemperC)
    result = y.float * Fact
  else:
    result = w.state[w.i].float * Fact

proc case5(w: Well44497a): float =
  w.z0 = (VRm1 and Maskl) or (VRm2 and Masku)
  w.z1 = mat0neg(-24, V0) xor mat0pos(30, VM1)
  w.z2 = mat0neg(-10, VM2Over) xor mat3neg(-26, VM3)
  newV1 = w.z1 xor w.z2
  newV0 = mat1(w.z0) xor 
          mat0pos(20, w.z1) xor 
          mat5(9,0xb729fcec'u32,0xfbffffff'u32,0x00020000'u32,w.z2) xor 
          mat1(newV1)
  dec w.i
  if (w.i + M2) < R:
    w.rng = case6
  when defined(Tempering):
    var y: uint32
    y = w.state[w.i] xor ((w.state[w.i] shl 7) and TemperB)
    y =            y xor ((           y shl 15) and TemperC)
    result = y.float * Fact
  else:
    result = w.state[w.i].float * Fact

proc case6(w: Well44497a): float =
  w.z0 = (VRm1 and Maskl) or (VRm2 and Masku)
  w.z1 = mat0neg(-24, V0) xor mat0pos(30, VM1)
  w.z2 = mat0neg(-10, VM2) xor mat3neg(-26, VM3)
  newV1 = w.z1 xor w.z2
  newV0 = mat1(w.z0) xor 
          mat0pos(20, w.z1) xor 
          mat5(9,0xb729fcec'u32,0xfbffffff'u32,0x00020000'u32,w.z2) xor 
          mat1(newV1)
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

proc newWell44497a*(init: openarray[uint32]): Well44497a =
  assert(len(init) == R)
  new(result)
  result.i = 0
  result.rng = case1
  for j in 0..<R:
    result.state[j] = init[j]
