import "../rngs"

const
  W = 32
  R = 32
  #P = 0
  M1 = 3 ## first parameter of the algorithm
  M2 = 24 ## second parameter of the algorithm
  M3 = 10 ## third parameter of the algorithm

type
  Well1024aObj = object of RandomNumberGeneratorObj
    state: array[R, int]
    i: int
    z0,z1,z2: int
  Well1024a* = ref Well1024aObj

const Fact = 2.32830643653869628906e-10'f64

proc mat0pos(t, v: int): int {.inline.} = v xor (v shr t)
proc mat0neg(t, v: int): int {.inline.} = v xor (v shl (-t))
proc identity(v: int): int {.inline.} = v
#proc mat3neg(t, v: int): int {.inline.} = v shl -t
#proc mat4neg(t, b, v: int): int {.inline.} = v xor ((v shl (-t)) and b)

template V0: int = w.state[w.i]
template VM1: int = w.state[(w.i+M1) and 0x0000001f]
template VM2: int = w.state[(w.i+M2) and 0x0000001f]
template VM3: int = w.state[(w.i+M3) and 0x0000001f]
template VRm1: int = w.state[(w.i+31) and 0x0000001f]
template newV0: expr = w.state[(w.i+31) and 0x0000001f]
template newV1: expr = w.state[w.i]

proc newWell1024a*(init: openarray[int]): Well1024a =
  assert(len(init) == 32)
  new(result)
  result.i = 0
  for j in 0..<R:
    result.state[j] = init[j]

proc well1024a*(w: Well1024a): float64 =
  w.z0 = VRm1
  w.z1 = identity(V0) xor mat0pos(8,VM1)
  w.z2 = mat0neg(-19,VM2) xor mat0neg(-14,VM3)
  newV1 = w.z1 xor w.z2
  newV0 = mat0neg(-11,w.z0) xor mat0neg(-7,w.z1) xor mat0neg(-13,w.z2)
  w.i = (w.i + 31) and 0x0000001f
  result = float64(w.state[w.i]) * Fact
