#/* rng/fishman2x.c
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
# * It is called "Fishman - L'Ecuyer"
# *
# * Nim implementation copyright (C) 2015 Jonathan Edwards,
# * based on GSL implementation (C) 2001 Carlo Perassi and
# * (C) 2003 Heiko Bauke.
# */

const
  ## Fishman
  AAA_F = 48271
  MMM_F = 0x7fffffff ## pow(2,31) - 1
  QQQ_F = 44488
  RRR_F = 3399
  ## L'Ecuyer
  AAA_L = 40692
  MMM_L = 0x7fffff07 ## pow(2,31) - 249
  QQQ_L = 527774
  RRR_L = 3791

import "../rngs"

type
  Fishman2xObj = object of RandomNumberGeneratorObj
    x,y,z: int ## state
  Fishman2x* = ref Fishman2xObj

proc newFishman2x*(seed = 1): Fishman2x =
  new(result)
  var seed = seed

  if (seed mod MMM_F) == 0 or (seed mod MMM_F) == 0:
    seed = 1

  result.x = seed mod MMM_F
  result.y = seed mod MMM_L
  result.z = if (result.x >% result.y):
                (result.x -% result.y) else:
                 MMM_F +% result.x -% result.y

proc next*(f: Fishman2x): int =
  var r = RRR_F *% (f.x /% QQQ_F)
  var y = AAA_F *% (f.x %% QQQ_F) -% r
  if y < 0:
    y = y +% MMM_F
  f.x = y

  r = RRR_L *% (f.y /% QQQ_L)
  y = AAA_L *% (f.y %% QQQ_L) -% r
  if y < 0:
    y = y +% MMM_L
  f.y = y

  f.z = if (f.x >% f.y): (f.x -% f.y) else: MMM_F +% f.x -% f.y

  result = f.z

proc nextFloat*(f: Fishman2x): float =
  result = next(f) / high(int32)
