#/*
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
# */

# Nim implementation 2015 Jonathan Edwards

import times
import bigints
import "../rngs"

type
  Rule30Obj = object of RandomNumberGeneratorObj
    w0,w1,w2: int64 ## the internal state
  Rule30* = ref Rule30Obj

proc setSeed*(r3: Rule30, w0,w1,w2: int64) =
  ## Set the seed using 3 long values
  const Blocks = 3
  const BitsPerBlock = 64

  var input = [w0,w1,w2] # pack into array to simplify algorithm
  var output: array[Blocks, int64] # tmp variable for holding state

  for j in 0..<(Blocks * BitsPerBlock):
    var inputBlock = j div BitsPerBlock
    var inputPos = j mod BitsPerBlock
    var outputBlock = j mod Blocks
    var outputPos = j div Blocks

    # get the bit we're working on
    if ((input[inputBlock] and (1 shl inputPos)) != 0):
      output[outputBlock] = output[outputBlock] or (1 shl outputPos)

  r3.w0 = output[0]
  r3.w1 = output[1]
  r3.w2 = output[2]

proc setSeed*(r3: Rule30, seed: int64) =
  ## Set the seed using a single long value
  r3.setSeed(0,seed,0)

proc getState*(r3: Rule30): seq[int64] =
  ## Get the internal state of the generator
  result = newSeq[int64](3)
  result[0] = r3.w0
  result[1] = r3.w1
  result[2] = r3.w2

proc newRule30*(): Rule30 =
  ## Default constructor
  new(result)
  result.setSeed(int(epochTime()))

proc newRule30*(arg0: int64): Rule30 =
  ## Seeded constructore
  new(result)
  result.setSeed(arg0)

proc next*(r3: Rule30, bits: int): int =
  var t0,t1,t2: int64

  var j = bits
  while j != 0:
    result = (result shl 1) or int((r3.w0 shr 32) and 1)
    t0 = ((r3.w2 shr 1) or (r3.w2 shl 63)) xor (r3.w0 or r3.w1)
    t2 = r3.w1 xor (r3.w2 or ((r3.w0 shl 1) or (r3.w0 shr 63)))
    t1 = r3.w0 xor (r3.w1 or r3.w2)
    r3.w0 = t0; r3.w1 = t1; r3.w2 = t2
    dec j
