#/* rng/coveyou.c
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
# * Section 3.2.2
# *
# * This implementation copyright (C) 2015 Jonathan Edwards, based on GSL implementation
# * (C) 2001 Carlo Perassi and (C) 2003 Heiko Bauke.
# */

import "../rngs"

type
  CoveyouObj = object of RandomNumberGeneratorObj
    val: int ## state
  Coveyou* = ref CoveyouObj

const MM = 0xffffffff ## pow(2, 32) - 1

proc newCoveyou*(seed: int): Coveyou =
  new(result)
  
  var diff = ((seed mod 4) - 2) mod MM

  if diff != 0:
    result.val = (seed - diff) and MM
  else:
    result.val = seed and MM

proc next*(c: Coveyou): int =
  c.val = (c.val *% (c.val +% 1)) and MM
  result = c.val

proc nextFloat*(c: Coveyou): float =
  result = next(c).toFloat / 4294967296.0
