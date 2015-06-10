# /* rng/knuthran.c
#  * 
#  * Nim implementation (C) 2015 Jonathan Edwards
#  * Copyright (C) 2001, 2007 Brian Gough, Carlo Perassi
#  * 
#  * This program is free software; you can redistribute it and/or modify
#  * it under the terms of the GNU General Public License as published by
#  * the Free Software Foundation; either version 3 of the License, or (at
#  * your option) any later version.
#  * 
#  * This program is distributed in the hope that it will be useful, but
#  * WITHOUT ANY WARRANTY; without even the implied warranty of
#  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  * General Public License for more details.
#  * 
#  * You should have received a copy of the GNU General Public License
#  * along with this program; if not, write to the Free Software
#  * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
#  */
# 
# /*
#  * This generator is taken from
#  *
#  * Donald E. Knuth
#  * The Art of Computer Programming
#  * Volume 2
#  * Third Edition
#  * Addison-Wesley
#  * Section 3.6
#  *
#  */

import "../rngs"

const
  Buflen = 2009
  KK = 100 ## the long lag
  LL = 37 ## the short lag
  MM = 1 shl 30 ## the modulus
  TT = 70 ## guaranteed separation between streams

proc evenize(x: int): int {.inline.} = x and (MM - 2)
proc isOdd(x: int): bool {.inline.} = (x and 1) != 0
proc modDiff(x,y: int): int {.inline.} = (x - y) and (MM - 1)

type
  KnuthRanObj = object of RandomNumberGeneratorObj
    i: int
    aa: array[Buflen, int]
    ranX: array[KK, int] ## state
  KnuthRan* = ref KnuthRanObj

proc newKnuthRan*(seed: int): KnuthRan =
  new(result)

  var x: array[KK+KK-1, int] # the preparation buffer
  var ss = evenize(seed + 2)

  for j in 0..<KK:
    x[j] = ss # bootstrap the buffer
    ss = ss shl 1
    if ss >= MM:
      ss = ss -% (MM - 2)
  for j in KK..<KK+KK-1:
    x[j] = 0
  inc x[1] # make x[1] (and only it) odd

  ss = seed and (MM - 1)
  var t = TT - 1

  while t != 0:
    for j in countdown(KK-1, 1):
      x[j + j] = x[j] # square
    for j in countdown(KK + KK - 2, KK - LL + 1, 2):
      x[KK + KK - 1 - j] = evenize(x[j])
    for j in countdown(KK + KK - 2, KK):
      if isOdd(x[j]):
        x[j - (KK - LL)] = modDiff(x[j - (KK - LL)], x[j])
        x[j - KK] = modDiff(x[j - KK], x[j])
    if isOdd(ss):
      for j in countdown(KK, 0+1):
        x[j] = x[j - 1]
      x[0] = x[KK]
      if isOdd(x[KK]):
        x[LL] = modDiff(x[LL],x[KK])
    if ss != 0:
      ss = ss shr 1
    else:
      dec t

  result.i = 0

  for j in 0..<LL:
    result.ranX[j + KK - LL] = x[j]
  for j in LL..<KK:
    result.ranX[j - LL] = x[j]

proc ranarray(aa: var openarray[int], n: int, 
              ranX: var openarray[int]) {.inline.} =
  for j in 0..<KK:
    aa[j] = ranX[j]

  for j in KK..<n:
    aa[j] = modDiff(aa[j - KK], aa[j - LL])

  var j = n
  for i in 0..<LL:
    ranX[i] = modDiff(aa[j - KK], aa[j - LL])
    inc j
  for i in LL..<KK:
    ranX[i] = modDiff(aa[j - KK], ranX[i - LL])
    inc j

proc next*(k: KnuthRan): int =
  var i = k.i
  if i == 0:
    ranarray(k.aa, Buflen, k.ranX)

  k.i = (i + 1) mod Buflen

  result = k.aa[i]

proc nextFloat*(k: KnuthRan): float =
  result = next(k).toFloat / 1073741824.0 # (high(int32) + 1) div 2
