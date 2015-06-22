#/* rng/fishman18.c
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
# * Page 106-108
# *
# * It is called "Fishman - Moore III"
# *
# * Nim implementation copyright (C) 2015 Jonathan Edwards,
# * based on GSL implementation (C) 2001 Carlo Perassi and
# * (C) 2003 Heiko Bauke.
# */

const
  AA = 62089911'i32
  MM = 0x7fffffff ## pow(2, 31) - 1

import "../rngs"

type
  Fishman18Obj = object of RandomNumberGeneratorObj
    val: int32 ## state
  Fishman18* = ref Fishman18Obj

proc newFishman18*(seed = 1): Fishman18 =
  new(result)

  var seed = seed
  if (seed mod MM) == 0:
    seed = 1

  result.val = seed mod MM

proc next*(f: Fishman18): int =
  f.val = AA *% f.val
  result = f.val.int

proc nextFloat*(f: Fishman18): float =
  result = next(f) / high(int32)
