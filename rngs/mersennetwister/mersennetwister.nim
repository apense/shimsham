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

# Nim implementation Copyright (C) 2015 Jonathan Edwards

import strutils, times
import "../rngs"

type
  MersenneTwisterObj= object of RandomNumberGeneratorObj
    mt: seq[int32] ## state vector
    mti: int32 ## int32ernal counter of position in state
  MersenneTwister* = ref MersenneTwisterObj

const
  N = 624 ## Internal array size
  M = 397 ## M
  Mag01 = [0x0, 0x9908b0df]

proc setSeed*(mt: MersenneTwister, seed: int32) =
  ## Initialize the pseudorandom number generator with 32 bits
  mt.mt[0] = seed
  var mti = mt.mti
  for mti in 1..<N:
    mt.mt[mti] = int32(1812433253'i32 *% mt.mt[mti - 1] xor (mt.mt[mti - 1] shr 30) +% mti)

proc setSeed*(mt: MersenneTwister, seed: openarray[int32]) =
  mt.setSeed(19650218)
  var k = if (N > len(seed)): N else: len(seed)
  var (i,j) = (1,0)
  while k != 0:
    mt.mt[i] = int32((mt.mt[i] xor 
                    ((mt.mt[i-1] xor (mt.mt[i-1] shr 30)) * 1664525)) + 
                      seed[j] + j)
    inc i
    inc j
    if i >= N:
      mt.mt[0] = mt.mt[N-1]
      i = 1
    if j >= len(seed):
      j = 0
    dec k
  k = N-1
  while k != 0:
    mt.mt[i] = int32((mt.mt[i] xor 
                    ((mt.mt[i-1] xor (mt.mt[i-1] shr 30)) * 1566083941)) - 
                      i)
    inc i
    if i >= N:
      mt.mt[0] = mt.mt[N-1]
      i = 1
    dec k
  mt.mt[0] = 0x80000000'i32

proc newMersenneTwister*(): MersenneTwister =
  new(result)
  result.mti = int32(len(result.mt) + 1)
  result.mt = newSeq[int32](N)
  setSeed(result, int32(epochTime()))

proc newMersenneTwister*(seed: int32): MersenneTwister =
  new(result)
  result.mti = int32(len(result.mt) + 1)
  result.mt = newSeq[int32](N)
  setSeed(result, seed)

proc newMersenneTwister*(seed:  openarray[int32]): MersenneTwister =
  new(result)
  result.mti = int32(len(result.mt) + 1)
  result.mt = newSeq[int32](N)
  setSeed(result, seed)

proc next*(mt: MersenneTwister, bits: int32 = 32): int32 =
  var y: int32
  if mt.mti >= N:
    var kk: int32 = 0
    while kk < (N - M):
      y = (mt.mt[kk] and 0x80000000'i32) or (mt.mt[kk+1] and 0x7fffffff)
      mt.mt[kk] = mt.mt[kk+M] xor int32(y shr 1) xor Mag01[y and 0x1].int32
      inc kk
    while kk < (N - 1):
      y = (mt.mt[kk] and 0x80000000'i32) or (mt.mt[kk+1] and 0x7fffffff)
      mt.mt[kk] = mt.mt[kk+(M-N)] xor int32(y shr 1) xor Mag01[y and 0x1].int32
      inc kk
    y = (mt.mt[N-1] and 0x80000000'i32) or (mt.mt[0] and 0x7fffffff)
    mt.mt[N-1] = mt.mt[M-1] xor int32(y shr 1) xor Mag01[y and 0x1].int32

    mt.mti = 0

  y = mt.mt[mt.mti]; inc mt.mti
  y = y xor (y shr 11)
  y = y xor ((y shl 7) and 0x9d2c5680'i32)
  y = y xor ((y shl 15) and 0xefc60000'i32)
  y = y xor (y shr 18)

  result = y shr (32 - bits)

proc nextHex*(mt: MersenneTwister, bits: int32): string =
  var ret = next(mt, bits)
  result = toHex(ret, if bits mod 4 == 0: bits div 4 else: bits div 4 + 1).toLower()

proc nextFloat*(mt: MersenneTwister, bits: int32 = 32): float =
  result = next(mt, bits) / high(int32)
