## Based off [Spire](https://github.com/non/spire/random/rng)
# Nim implementation 2015 Jonathan Edwards

import times
import "../rngs"

type
  ## list taken from <https://en.wikipedia.org/wiki/Linear_congruential_generator>_
  Lcg64Type* = enum
    MMIX = 0
    Newlib

const Lcg64Vals = {
  MMIX: [6364136223846793005,1442695040888963407],
  Newlib: [6364136223846793005,1],
}

type
  Lcg64Obj = object of RandomNumberGeneratorObj
    seed: BiggestInt ## state
    lcg: Lcg64Type
  Lcg64* = ref Lcg64Obj

proc newLcg64*(lcg = MMIX): Lcg64 =
  new(result)
  result.seed = int64(epochTime())
  result.lcg = lcg

proc newLcg64*(seed: int64, lcg = MMIX): Lcg64 =
  new(result)
  result.seed = seed
  result.lcg = lcg

proc next*(lcg: Lcg64): int64 =
  var (a,c) = (Lcg64Vals[int(lcg.lcg)][1][0],Lcg64Vals[int(lcg.lcg)][1][1])
  lcg.seed = a *% lcg.seed +% c
  result = lcg.seed

proc nextFloat*(lcg: Lcg64): float =
  result = next(lcg).float / high(int64).float
