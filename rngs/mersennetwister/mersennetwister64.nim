# * Copyright 2005, Nick Galbreath -- nickg [at] modp [dot] com
# * All rights reserved.
# *
# * Redistribution and use in source and binary forms, with or without
# * modification, are permitted provided that the following conditions are
# * met:
# *
# *   Redistributions of source code must retain the above copyright
# *   notice, this list of conditions and the following disclaimer.
# *
# *   Redistributions in binary form must reproduce the above copyright
# *   notice, this list of conditions and the following disclaimer in the
# *   documentation and/or other materials provided with the distribution.
# *
# *   Neither the name of the modp.com nor the names of its
# *   contributors may be used to endorse or promote products derived from
# *   this software without specific prior written permission.
# *
# * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# *
# * This is the standard "new" BSD license:
# * http://www.opensource.org/licenses/bsd-license.php
# *
# * Portions may also be
# * Copyright (C) 1997 - 2002, Makoto Matsumoto and Takuji Nishimura,
# * All rights reserved.
# * (and covered under the BSD license)
# * See http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/MT2002/CODES/mt19937ar.c

# Nim implementation copyright (C) 2015 Jonathan Edwards

import strutils, times
from math import pow
import "../rngs"

const
  NN = 312 ## Internal array size
  MM = 156 ## MM
  MatrixA = 0xb5026f5aa96619e9'i64
  UM = 0xffffffff80000000'i64 ## Most significant 33 bits
  LM = 0x000000007fffffff'i64 ## Least significant 31 bits
  Mag01 = [0'i64, MatrixA]

type
  MersenneTwister64Obj= object of RandomNumberGeneratorObj
    mt: array[NN,int64] ## state vector
    mti: int ## internal counter of position in state
    bits: int64 ## internal to hold 64 bits
    bitState: bool
  MersenneTwister64* = ref MersenneTwister64Obj

proc setSeed*(mt: MersenneTwister64, seed: int64) =
  ## Initialize the pseudorandom number generator with 32 bits
  mt.mt[0] = seed
  var mti = mt.mti
  for mti in 1..<NN:
    mt.mt[mti] = 6364136223846793005'i64 *% 
                (mt.mt[mti - 1] xor (mt.mt[mti - 1] shr 62)) +% mti

proc setSeed*(mt: MersenneTwister64, seed: openarray[int64]) =
  mt.setSeed(19650218)
  var k = max(NN, len(seed))
  var (i,j) = (1,0)
  while k != 0:
    mt.mt[i] = (mt.mt[i] xor 
              ((mt.mt[i-1] xor (mt.mt[i-1] shr 62)) *% 
                3935559000370003845'i64)) +% seed[j] +% j
    inc i
    inc j
    if i >= NN:
      mt.mt[0] = mt.mt[NN-1]
      i = 1
    if j >= len(seed):
      j = 0
    dec k
  k = NN-1
  while k != 0:
    mt.mt[i] = (mt.mt[i] xor 
              ((mt.mt[i-1] xor (mt.mt[i-1] shr 62)) *% 
                2862933555777941757'i64)) -% i
    inc i
    if i >= NN:
      mt.mt[0] = mt.mt[NN-1]
      i = 1
    dec k
  mt.mt[0] = 1 shl 63

proc newMersenneTwister64*(): MersenneTwister64 =
  new(result)
  result.mti = int(NN + 1)
  result.bitState = true
  setSeed(result, int(epochTime()))

proc newMersenneTwister64*(seed: int64): MersenneTwister64 =
  new(result)
  result.mti = int(NN + 1)
  result.bitState = true
  setSeed(result, seed)

proc newMersenneTwister64*(seed:  openarray[int64]): MersenneTwister64 =
  new(result)
  result.mti = int(NN + 1)
  result.bitState = true
  setSeed(result, seed)

proc next64*(mt: MersenneTwister64): int64 =
  var i: int32 = 0
  var x: int64
  if mt.mti >= NN:
    while i < (NN-MM):
      x = (mt.mt[i] and UM) or (mt.mt[i+1] and LM)
      mt.mt[i] = mt.mt[i + MM] xor ((x shr 1) xor Mag01[x and 1])
      inc i
    while i < (NN - 1):
      x = (mt.mt[i] and UM) or (mt.mt[i+1] and LM)
      mt.mt[i] = mt.mt[i + (MM - NN)] xor (x shr 1) xor Mag01[x and 1]
      inc i
    x = (mt.mt[NN-1] and UM) or (mt.mt[0] and LM)
    mt.mt[NN-1] = mt.mt[MM-1] xor (x shr 1) xor Mag01[x and 1]

    mt.mti = 0

  x = mt.mt[mt.mti]; inc mt.mti

  x = x xor ((x shr 29) and 0x5555555555555555'i64)
  x = x xor ((x shl 17) and 0x71d67fffeda60000'i64)
  x = x xor ((x shl 37) and 0xfff7eee000000000'i64)
  x = x xor (x shr 43)

  result = x

proc next*(mt: MersenneTwister64, numbits: int = 32): int32 =
  if mt.bitState:
    mt.bits = next64(mt)
    mt.bitState = false
    result = toU32(mt.bits shr (64 - numbits))
  else:
    mt.bitState = true
    result = toU32(toU32(mt.bits) shr (32 - numbits))

proc nextFloat*(mt: MersenneTwister64, numbits: int = 32): float =
  result = next(mt, numbits) / int(pow(2.0,numbits.toFloat) - 1)

proc nextHex*(mt: MersenneTwister64, numbits: int = 32): string =
  var ret = next(mt, numbits)
  result = toHex(ret, if numbits mod 4 == 0: 
                         numbits div 4 else: 
                         numbits div 4 + 1).toLower()
