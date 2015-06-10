#/* rng/borosh13.c
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
# * It is called "Borosh - Niederreiter"
# *
# * This implementation copyright (C) 2015 Jonathan Edwards, based on GSL implementation
# * (C) 2001 Carlo Perassi and (C) 2003 Heiko Bauke.
# */

import "../rngs"

const
  AA = 1812433253
  MM = 0xffffffff ## pow(2, 32) - 1

type
  Borosh13Obj = object of RandomNumberGeneratorObj
    val: int ## state
  Borosh13* = ref Borosh13Obj

proc newBorosh13*(seed = 1): Borosh13 =
  new(result)
  result.val = seed

proc next*(b: Borosh13): int =
  b.val = (AA * b.val) and MM
  result = b.val

proc nextFloat*(b: Borosh13): float =
  result = next(b).toFloat / 4294967296.0
