## Adapted from BouncyCastle

import unsigned

proc `|=`[T](x: var T, y: T) =
  x = x or y
proc `<<=`[T](x: var T, y: T) =
  x = x shl y
proc `^=`[T](x: var T, y: T) =
  x = x xor y

type
  Keccak* = object
    state: array[1600 div 8, byte]
    dataQueue: array[1536 div 8, byte]
    rate: int
    bitsInQueue: int
    fixedOutputLength: int
    squeezing: bool
    bitsAvailableForSqueezing: int
    chunk: seq[byte]
    oneByte: seq[byte]

proc keccakInitialzeRhoOffsets(): seq[int] =
  result = newSeq[int](25)
  var x,y,t,newx,newy: int 

  var rhoOffset = 0
  result[(((0) mod 5) + 5 * ((0) mod 5))] = rhoOffset
  x = 1
  y = 0
  for t in 1..<25:
    rhoOffset = (rhoOffset + t) and 63
    result[(((x) mod 5) + 5 * ((y) mod 5))] = rhoOffset
    newx = (0 * x + 1 * y) mod 5
    newy = (2 * x + 3 * y) mod 5
    x = newx
    y = newy

proc keccakInitialzeRoundConstants(): seq[uint64] =
  result = newSeq[uint64](24)
  var LFSRstate = 0x01  
  var bitposition: int

  for i in 0..<24:
    result[i] = 0
    for j in 0..<7:
      var lobit = (LFSRstate and 0x01) != 0
      if lobit:
        result[i] = result[i] xor (1'u64 shl bitposition.uint64)
      var hibit = (LFSRstate and 0x80) != 0
      LFSRstate = LFSRstate shl 1
      if hibit:
        LFSRstate = LFSRstate xor 0x71

proc initSponge(rate, capacity: int): Keccak =
  if (rate + capacity) != 1600:
    raise newException(ValueError, "rate + capacity != 1600")
  if (rate <= 0) or (rate >= 1600) or ((rate mod 64) != 0):
    raise newException(ValueError, "invalid rate value")

  result.rate = rate
  #result.capacity = capacity
  result.fixedOutputLength = 0
  result.bitsInQueue = 0
  result.squeezing = false
  result.bitsAvailableForSqueezing = 0
  result.fixedOutputLength = capacity div 2
  result.chunk = newSeq[byte](rate div 8)
  result.oneByte = newSeq[byte](1)

proc initKeccak*(bitlength: int): Keccak =
  case bitlength
  of 0, 288:
    result = initSponge(1024, 576)
  of 224:
    result = initSponge(1152, 448)
  of 256:
    result = initSponge(1088, 512)
  of 384:
    result = initSponge(832, 768)
  of 512: 
    result = initSponge(576, 1024)
  else:
    raise newException(ValueError, "bitlength must be in {224,256,384,512}")

proc getAlgorithm*(k: Keccak): string =
  result = "SHA3-" & $k.fixedOutputLength

proc getDigestSize*(k: Keccak): int =
  result = k.fixedOutputLength div 8

proc getByteLength*(k: Keccak): int =
  result = k.rate div 8

proc reset*(k: var Keccak) =
  k = initKeccak(k.fixedOutputLength)

proc bytesToWords(stateAsWords: var openarray[uint64], state: openarray[byte]) =
  for i in 0..<(1600 div 64):
    stateAsWords[i] = 0
    let index = i * (64 div 8)
    for j in 0..<(64 div 8):
      stateAsWords[i] = stateAsWords[i] or (uint64(state[index + j] and 0xff) shl uint64(8 * j))

proc wordsToBytes(state: var openarray[byte], stateAsWords: openarray[uint64]) =
  for i in 0..<(1600 div 64):
    let index = i * (64 div 8)
    for j in 0..<(64 div 8):
      state[index + j] = byte((stateAsWords[i] shr uint64(8 * j)) and 0xff)

let KeccakRhoOffsets = keccakInitialzeRhoOffsets()
let KeccakRoundConstants = keccakInitialzeRoundConstants()

var C: array[5, uint64]

proc theta(A: var openarray[uint64]) =
  for x in 0..<5:
    C[x] = 0
    for y in 0..<5:
      C[x] = C[x] xor A[x + 5 * y]
  for x in 0..<5:
    let dX = ((((C[(x + 1) mod 5]) shl 1) xor ((C[(x + 1) mod 5]) shr (64 - 1)))) xor C[(x + 4) mod 5]
    for y in 0..<5:
      A[x + 5 * y] = A[x + 5 * y] xor dX

proc rho(A: var openarray[uint64]) =
  for x in 0..<5:
    for y in 0..<5:
      let index = x + 5 * y
      A[index] = (if(KeccakRhoOffsets[index] != 0): 
                  (((A[index]) shl KeccakRhoOffsets[index].uint64) xor ((A[index]) shr 
                    uint64(64 - KeccakRhoOffsets[index]))) else: 
                     A[index])

var tempA: array[25, uint64]

proc pi(A: var openarray[uint64]) =
  for i in 0..<tempA.len:
    tempA[i] = A[i]
  for x in 0..<5:
    for y in 0..<5:
      A[y + 5 * ((2 * x + 3 * y) mod 5)] = tempA[x + 5 * y]

var chiC: array[5, uint64]

proc chi(A: var openarray[uint64]) =
  for y in 0..<5:
    for x in 0..<5:
      chiC[x] = (A[x + 5 * y] xor ((not A[(((x + 1) mod 5) + 5 * y)]) and A[(((x + 2) mod 5) + 5 * y)]))
    for x in 0..<5:
      A[x + 5 * y] = chiC[x]

proc iota(A: var openarray[uint64], indexRound: int) =
  A[(((0) mod 5) + 5 * ((0) mod 5))] ^= KeccakRoundConstants[indexRound]

proc keccakExtract(byteState: openarray[byte], data: var openarray[byte], laneCount: int) =
  for i in 0..<laneCount*8:
    data[i] = byteState[i]

proc keccakExtract1024bits(byteState: openarray[byte], data: var openarray[byte]) =
  for i in 0..<128:
    data[i] = byteState[i]

proc keccakPermutationOnWords(state: var openarray[uint64]) =
  for i in 0..<24:
    theta(state)
    rho(state)
    pi(state)
    chi(state)
    iota(state, i)

proc keccakPermutation(state: var openarray[byte]) =
  var longState = newSeq[uint64](state.len div 8)
  bytesToWords(longState, state)
  keccakPermutationOnWords(longState)
  wordsToBytes(state, longState)

proc keccakPermutationAfterXor(state: var openarray[byte], data: openarray[byte], dataLengthInBytes: int) =
  for i in 0..<dataLengthInBytes:
    state[i] = state[i] xor data[i]
  keccakPermutation(state)

proc keccakAbsorb(byteState: var openarray[byte], data: openarray[byte], dataInBytes: int) =
  keccakPermutationAfterXor(byteState, data, dataInBytes)

proc absorbQueue(k: var Keccak) =
  keccakAbsorb(k.state, k.dataQueue, k.rate div 8)
  k.bitsInQueue = 0

proc absorb(k: var Keccak, data: openarray[byte], offset = 0, databitlen: int = 0) =
  if (k.bitsInQueue mod 8) != 0:
    raise newException(ValueError, "attempt to absorb with odd length queue")
  if k.squeezing:
    raise newException(ValueError, "attempt to absorb while squeezing")

  var i = 0
  var wholeblocks: int
  while i < databitlen:
    if (k.bitsInQueue == 0) and (databitlen >= k.rate) and (i <= (databitlen - k.rate)):
      wholeblocks = (databitlen - i) div k.rate
      for j in 0..<wholeblocks:
        for n in 0..<k.chunk.len:
          k.chunk[n] = data[n + offset + (i div 8) + (j * k.chunk.len)]
        keccakAbsorb(k.state, k.chunk, k.chunk.len)
      i += wholeblocks * k.rate
    else:
      var partialBlock = (databitlen - i)
      if (partialBlock + k.bitsInQueue) > k.rate:
        partialBlock = k.rate - k.bitsInQueue
      var partialByte = partialBlock mod 8
      partialBlock -= partialByte
      for n in 0..<(partialBlock div 8):
        k.dataQueue[n + k.bitsInQueue div 8] = data[n + offset + i div 8]
      k.bitsInQueue += partialBlock
      i += partialBlock
      if k.bitsInQueue == k.rate:
        k.absorbQueue()
      if partialByte > 0:
        var mask = (1 shl partialByte) - 1
        k.dataQueue[k.bitsInQueue div 8] = byte(int(data[offset + int(i div 8)]) and mask)
        k.bitsInQueue += partialByte
        i += partialByte

proc clearDataQueueSection(k: var Keccak, offset, length: int) =
  for i in offset..<offset+length:
    k.dataQueue[i] = 0

proc padAndSwitchToSqueezingPhase(k: var Keccak) =
  if (k.bitsInQueue + 1) == k.rate:
    k.dataQueue[k.bitsInQueue div 8] = k.dataQueue[k.bitsInQueue div 8] or byte(1 shl (k.bitsInQueue mod 8))
    k.absorbQueue()
    k.clearDataQueueSection(0, k.rate div 8)
  else:
    k.clearDataQueueSection((k.bitsInQueue + 7) div 8, k.rate div 8 - (k.bitsInQueue + 7) div 8)
    k.dataQueue[k.bitsInQueue div 8] = k.dataQueue[k.bitsInQueue div 8] or byte(1 shl (k.bitsInQueue mod 8))
  k.dataQueue[(k.rate - 1) div 8] = k.dataQueue[(k.rate - 1) div 8] or byte(1 shl ((k.rate - 1) mod 8))
  k.absorbQueue()

  if k.rate == 1024:
    keccakExtract1024bits(k.state, k.dataQueue)
    k.bitsAvailableForSqueezing = 1024
  else:
    keccakExtract(k.state, k.dataQueue, k.rate div 64)
    k.bitsAvailableForSqueezing = k.rate

  k.squeezing = true

proc squeeze(k: var Keccak, output: var openarray[byte], offset, outputLength: int) =
  var partialBlock: int

  if not k.squeezing:
    k.padAndSwitchToSqueezingPhase()
  if (outputLength mod 8) != 0:
    raise newException(ValueError, "outputLength not a multiple of 8")

  var i = 0
  while i < outputLength:
    if k.bitsAvailableForSqueezing == 0:
      keccakPermutation(k.state)

      if k.rate == 1024:
        keccakExtract1024bits(k.state, k.dataQueue)
        k.bitsAvailableForSqueezing = 1024
      else:
        keccakExtract(k.state, k.dataQueue, k.rate div 64)
        k.bitsAvailableForSqueezing = k.rate
    partialBlock = k.bitsAvailableForSqueezing
    if partialBlock > (outputLength - i):
      partialBlock = outputLength - i

    for j in 0..<(partialBlock div 8):
      output[j + offset + (i div 8)] = k.dataQueue[j + (k.rate - k.bitsAvailableForSqueezing) div 8]
    k.bitsAvailableForSqueezing -= partialBlock
    i += partialBlock

proc doFinal(k: var Keccak, output: var openarray[byte], offset: int): int {.discardable.} =
  k.squeeze(output, offset, k.fixedOutputLength)
  k.reset()
  result = k.getDigestSize()

proc doUpdate(k: var Keccak, data: openarray[byte], offset, databitlen: int) =
  if (databitlen mod 8) == 0:
    k.absorb(data, offset, databitlen)
  else:
    k.absorb(data, offset, databitlen - (databitlen mod 8))
    var lastbyte = newSeq[byte](1)
    lastbyte[0] = byte(int(data[offset + int(databitlen div 8)]) shr int(8 - (databitlen mod 8)))
    k.absorb(lastbyte, offset, databitlen mod 8)

proc Sha3*(bitlength: int = 0): Keccak = 
  result = initKeccak(bitlength)

proc update*(k: var Keccak, input: byte) =
  k.oneByte[0] = input
  k.doUpdate(k.oneByte, 0, 8)

proc blockUpdate*(k: var Keccak, input: openarray[byte], inOffset, inLen: int) =
  k.doUpdate(input, inOffset, inLen * 8)

var k = initKeccak(224)
var hash = newSeq[byte](k.getDigestSize())
k.doFinal(hash,0)

import strutils
var res = ""
for i in hash:
  res.add(toHex(i.int, 2).toLower())
echo res