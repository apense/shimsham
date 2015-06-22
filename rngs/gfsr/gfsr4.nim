# /* This program is free software; you can redistribute it and/or
#    modify it under the terms of the GNU General Public License as
#    published by the Free Software Foundation; either version 3 of the
#    License, or (at your option) any later version.
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#    General Public License for more details.  You should have received
#    a copy of the GNU General Public License along with this library; if
#    not, write to the Free Software Foundation, Inc., 51 Franklin Street,
#    Fifth Floor, Boston, MA 02110-1301, USA.
#    From Robert M. Ziff, "Four-tap shift-register-sequence
#    random-number generators," Computers in Physics 12(4), Jul/Aug
#    1998, pp 385-392.  A generalized feedback shift-register (GFSR)
#    is basically an xor-sum of particular past lagged values.  A
#    four-tap register looks like:
#       ra[nd] = ra[nd-A] ^ ra[nd-B] ^ ra[nd-C] ^ ra[nd-D]
#
#    Ziff notes that "it is now widely known" that two-tap registers
#    have serious flaws, the most obvious one being the three-point
#    correlation that comes from the defn of the generator.  Nice
#    mathematical properties can be derived for GFSR's, and numerics
#    bears out the claim that 4-tap GFSR's with appropriately chosen
#    offsets are as random as can be measured, using the author's test.
#    This implementation uses the values suggested the the author's
#    example on p392, but altered to fit the GSL framework.  The "state"
#    is 2^14 longs, or 64Kbytes; 2^14 is the smallest power of two that
#    is larger than D, the largest offset.  We really only need a state
#    with the last D values, but by going to a power of two, we can do a
#    masking operation instead of a modulo, and this is presumably
#    faster, though I haven't actually tried it.  The article actually
#    suggested a short/fast hack:
#    #define RandomInteger (++nd, ra[nd&M]=ra[(nd-A)&M]\
#                           ^ra[(nd-B)&M]^ra[(nd-C)&M]^ra[(nd-D)&M])
#    so that (as long as you've defined nd,ra[M+1]), then you ca do things
#    like: 'if (RandomInteger < p) {...}'.
#    Note that n&M varies from 0 to M, *including* M, so that the
#    array has to be of size M+1.  Since M+1 is a power of two, n&M
#    is a potentially quicker implementation of the equivalent n%(M+1).
#    This implementation copyright (C) 1998 James Theiler, based on
#    the example mt.c in the GSL, as implemented by Brian Gough.
# */

# Altered from the above: The constants from the paper as as they were (not altered)
# to fit GSL's framework. Implementation (C) 2015 Jonathan Edwards

import "../rngs"

const
  A = 471
  B = 1586
  C = 6988
  D = 9689
  M = 16383

type
  Gfsr4Obj = object of RandomNumberGeneratorObj
    nd: int
    ra: array[M+1, int] ## state
  Gfsr4* = ref Gfsr4Obj

proc LCG(n: int): int {.inline, noSideEffect.} = (69069 *% n)

proc newGfsr4*(seed: int = 4357): Gfsr4 =
   new(result)

   var msb = 0x80000000
   var mask = 0xffffffff

   var seed = seed

   for i in 0..M:
      var t = 0
      var bit = msb
      for j in 0..<32:
         seed = LCG(seed)
         if (seed and msb) != 0:
            t = t or bit
         bit = bit shr 1
      result.ra[i] = t

   for i in 0..<32:
      var k = 7 + i * 3
      result.ra[k] = result.ra[k] and mask # turn off bits left of diagonal
      result.ra[k] = result.ra[k] or msb # turn on diagonal bit
      mask = mask shr 1
      msb = msb shr 1

   result.nd = 32

proc next*(g: Gfsr4): int =
   g.nd = (g.nd + 1) and M

   g.ra[g.nd] = g.ra[(g.nd + M + 1 - A) and M] xor
                g.ra[(g.nd + M + 1 - B) and M] xor
                g.ra[(g.nd + M + 1 - C) and M] xor
                g.ra[(g.nd + M + 1 - D) and M]

   result = g.ra[g.nd]

proc nextFloat*(g: Gfsr4): float =
   result = next(g).toFloat / 4294967296.0 # high(uint32) + 1
