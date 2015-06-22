#/* rng/fishman20.c
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
# * It is called "Fishman"
# *
# * Nim implementation copyright (C) 2015 Jonathan Edwards,
# * based on GSL implementation (C) 2001 Carlo Perassi and
# * (C) 2003 Heiko Bauke.
# */

const
  m = 2147483647
  a = 48271
  q = 44488
  r = 3399

import "../rngs"

type
  Fishman20Obj = object of RandomNumberGeneratorObj
    val: int ## state
  Fishman20* = ref Fishman20Obj

proc newFishman20*(seed = 1): Fishman20 =
  new(result)

  var seed = seed

  if seed mod m == 0:
    seed = 1

  result.val = seed mod m

proc next*(f: Fishman20): int =
  let val = f.val
  let h = val div q
  let t = a *% (val -% h *% q) -% h *% r

  if t < 0:
    f.val = t +% m
  else:
    f.val = t

  result = f.val

proc nextFloat*(f: Fishman20): float =
  result = next(f) / high(int32)

