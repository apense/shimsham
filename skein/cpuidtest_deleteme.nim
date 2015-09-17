
const
  RandSizeLen = 8
  RandSize = 1 shl RandSizeLen
  RandSizeUSize = 1 shl RandSizeLen
  RandSize64Len = 8
  RandSize64 = 1 shl RandSize64Len

type
  IsaacRng = object
    cnt: int32
    rsl: array[RandSizeUSize, int32]
    mem: array[RandSizeUSize, int32]
    a, b, c: int32

let Empty = IsaacRng()

proc isaac(i: var IsaacRng) =
  i.c = i.c +% 1
  # abbreviations
  var (a, b) = (i.a, i.b + i.c)

  const Midpoint = RandSizeUSize div 2

  template ind(x: expr): int32 =
    mem[(x shr 2) and (RandSizeUSize - 1)]

  let r = [(0, Midpoint), (Midpoint, 0)]

  for mr, m2 in r.items:
    var mem = i.mem
    var rsl = i.rsl
    template rngstepp(j, shift) =
      let base = j
      let mix = a shl shift

      let x = mem[base + mr]
      a = (a xor mix) +% mem[base + m2]
      let y = ind(x) +% a +% b
      mem[base + mr] = y

      b = ind(y shr RandSizeLen) +% x
      rsl[base + mr] = b

    template rngstepn(j, shift) =
      let base = j
      let mix = a shr shift

      let x = mem[base + mr]
      a = (a xor mix) +% mem[base + m2]
      let y = ind(x) +% a +% b
      mem[base + mr] = y

      b = ind(y shr RandSizeLen) +% x
      rsl[base + mr] = b

    for i in countup(0, Midpoint-1, 4):
      rngstepp(i + 0, 13)
      rngstepn(i + 1,  6)
      rngstepp(i + 2,  2)
      rngstepn(i + 3, 16)
    i.mem = mem
    i.rsl = rsl

  i.a = a
  i.b = b
  i.cnt = RandSize

proc init*(rng: var IsaacRng, useRsl: bool) =
  var a = 0x9e3779b9'i32
  var (b,c,d,e,f,g,h) = (a,a,a,a,a,a,a)

  template mix() =
    a = a xor (b shl 11); d = d +% a; b = b +% c
    b = b xor (c shr  2); e = e +% b; c = c +% d
    c = c xor (d shl  8); f = f +% c; d = d +% e
    d = d xor (e shr 16); g = g +% d; e = e +% f
    e = e xor (f shl 10); h = h +% e; f = f +% g
    f = f xor (g shr  4); a = a +% f; g = g +% h
    g = g xor (h shl  8); b = b +% g; h = h +% a
    h = h xor (a shr  9); c = c +% h; a = a +% b

  for _ in 0..<4:
    mix()

  if useRsl:
    template memloop(arr: expr) =
      for i in countup(0,RandSizeUSize-1,8):
        a = a +% arr[i  ]; b = b +% arr[i+1]
        c = c +% arr[i+2]; d = d +% arr[i+3]
        e = e +% arr[i+4]; f = f +% arr[i+5]
        g = g +% arr[i+6]; h = h +% arr[i+7]
        mix()
        rng.mem[i  ] = a; rng.mem[i+1] = b
        rng.mem[i+2] = c; rng.mem[i+3] = d
        rng.mem[i+4] = e; rng.mem[i+5] = f
        rng.mem[i+6] = g; rng.mem[i+7] = h
    memloop(rng.rsl)
    memloop(rng.mem)
  else:
    for i in countup(0, RandSizeUSize-1, 8):
      mix()
      rng.mem[i  ] = a; rng.mem[i+1] = b
      rng.mem[i+2] = c; rng.mem[i+3] = d
      rng.mem[i+4] = e; rng.mem[i+5] = f
      rng.mem[i+6] = g; rng.mem[i+7] = h

  rng.isaac()


proc initUnseeded(): IsaacRng =
  var rng = Empty
  init(rng,false)
  result = rng

proc reseed(rng: var IsaacRng, seed: openarray[int32]) =
  for i in 0..<len(seed):
    rng.rsl[i] = seed[i]

  rng.cnt = 0
  rng.a = 0
  rng.b = 0
  rng.c = 0
  rng.init(true)

proc initFromSeed(seed: openarray[int32]): IsaacRng =
  var rng = Empty
  rng.reseed(seed)
  result = rng

proc nextu32(rng: var IsaacRng): uint32 =
  if rng.cnt == 0:
    # make some more numbers
    rng.isaac()
  dec rng.cnt

  assert(rng.cnt < RandSize)

  result = uint32(rng.rsl[(rng.cnt mod RandSize)])

let seed = [1'i32, 23, 456, 7890, 12345]
var r = initFromSeed(seed)
