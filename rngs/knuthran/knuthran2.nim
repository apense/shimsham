#/* rng/knuthran2.c
# * 
# * This program is free software; you can redistribute it and/or modify
# * it under the terms of the GNU General Public License as published by
# * the Free Software Foundation; either version 3 of the License, or (at
# * your option) any later version.
# * 
# * This program is distributed in the hope that it will be useful, but
# * WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# * General Public License for more details.
# * 
# * You should have received a copy of the GNU General Public License
# * along with this program; if not, write to the Free Software
# * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
# */
#
#/*
# * This generator is taken from
# *
# * Donald E. Knuth
# * The Art of Computer Programming
# * Volume 2
# * Third Edition
# * Addison-Wesley
# * Page 108
# *
# * GSL C implementation  copyright (C) 2001 Carlo Perassi
# * and (C) 2003 Heiko Bauke.
# */

# Nim implementation copyright (C) 2015 Jonathan Edwards

import "../rngs"

const
  AA1 = 271828183'i32 ## e
  AA2 = 1833324378'i32 ## -314159269 mod (pow(2,31) - 1)
  MM = 0x7fffffff ## pow(2,31) - 1

type
  KnuthRan2Obj = object of RandomNumberGeneratorObj
    x0,x1: int32 ## state
  KnuthRan2* = ref KnuthRan2Obj

proc newKnuthRan2*(seed = 1): KnuthRan2 =
  new(result)

  var seed = seed

  if (seed mod MM) == 0:
    seed = 1

  result.x0 = seed mod MM
  result.x1 = seed mod MM

proc next*(k: KnuthRan2): int =
  var tmp = k.x1

  k.x1 = AA1 *% k.x1 +% AA2 *% k.x0

  if k.x1 >= MM:
    k.x1 -= MM

  k.x0 = tmp

  result = k.x1

proc nextFloat*(k: KnuthRan2): float =
  result = next(k) / high(int32)
