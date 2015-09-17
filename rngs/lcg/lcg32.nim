# Nim implementation 2015 Jonathan Edwards
import times
import "../rngs"

type
  ## list taken from <https://en.wikipedia.org/wiki/Linear_congruential_generator>_
  Lcg32Type* = enum
    NumRecipes = 0 ## Numerical Recipes in C
    Borland
    Glibc ## also ANSI and C99/C11
    Delphi
    VisualC
    VisualBasic
    NativeAPI
    CarbonLib
    Cpp11
    VMS

const Lcg32Vals = {
  NumRecipes: [1664525'i32, 1013904223],
  Borland: [22695477'i32, 1],
  Glibc: [1103515245'i32, 12345],
  Delphi: [134775813'i32, 1],
  VisualBasic: [214013'i32, 2531011],
  VisualBasic: [1140671485'i32, 12820163],
  NativeAPI: [2147483629'i32, 2147483587],
  CarbonLib: [16807'i32, 0],
  Cpp11: [48271'i32, 0],
  VMS: [69069'i32, 1]
}

type
  Lcg32Obj = object of RandomNumberGeneratorObj
    seed: int32 ## state
    lcg: Lcg32Type
  Lcg32* = ref Lcg32Obj

proc newLcg32*(lcg = NumRecipes): Lcg32 =
  new(result)
  result.seed = int32(epochTime())
  result.lcg = lcg

proc newLcg32*(seed: int32, lcg = NumRecipes): Lcg32 =
  new(result)
  result.seed = seed
  result.lcg = lcg

proc next*(lcg: Lcg32): int32 =
  var (a,c) = (Lcg32Vals[int(lcg.lcg)][1][0],Lcg32Vals[int(lcg.lcg)][1][1])
  lcg.seed = a *% lcg.seed +% c
  result = lcg.seed

proc nextFloat*(lcg: Lcg32): float =
  result = next(lcg) / high(int32)
