include pool_consts
import strutils, unsigned

type
  Whirlpool* = object ## Represents the partial evaluation of a checksum
    bitLength*: array[LengthBytes, byte] ## number of hashed bits
    buffer*: array[WBlockBytes, byte] ## buffer of data to be hashed
    bufferBits*: int ## current number of bits on the buffer
    bufferPos*: int ## current bytes location on buffer
    hash*: array[DigestBytes div 8, uint64] ## hash state

proc getUint64(b: seq[byte]): uint64 =
  result = (uint64(b[7])       ) or 
           (uint64(b[6]) shl  8) or 
           (uint64(b[5]) shl 16) or 
           (uint64(b[4]) shl 24) or
           (uint64(b[3]) shl 32) or 
           (uint64(b[2]) shl 40) or 
           (uint64(b[1]) shl 48) or 
           (uint64(b[0]) shl 56)

proc reset*(w: var Whirlpool) =
  # clean up the buffer
  reset(w.buffer)
  w.bufferBits = 0
  w.bufferPos = 0

  # clean up the digest
  reset(w.hash)

  # clean up the number of hashed bits
  reset(w.bitLength)

proc size*(w: Whirlpool): int =
  result = DigestBytes

proc blocksize*(w: Whirlpool): int =
  result = WBlockBytes

proc transform(w: var Whirlpool) =
  var
    K: array[8, uint64] # round key
    blk: array[8, uint64] # μ (the buffer)
    state: array[8, uint64] # cipher state
    L: array[8, uint64]

  # map the buffer to a block
  for i in 0..<8:
    var b = 8*i
    blk[i] = getUint64(w.buffer[b..^1])

  # compute and apply K^0 to the cipher state
  for i in 0..<8:
    K[i] = w.hash[i]
    state[i] = blk[i] xor K[i]

  # iterate over all the rounds
  for r in 1..Rounds:
    # compute K^rounds from K^(rounds-1)
    for i in 0..<8:
      L[i] = C0[byte(K[ i    mod 8] shr 56)] xor
             C1[byte(K[(i+7) mod 8] shr 48)] xor
             C2[byte(K[(i+6) mod 8] shr 40)] xor
             C3[byte(K[(i+5) mod 8] shr 32)] xor
             C4[byte(K[(i+4) mod 8] shr 24)] xor
             C5[byte(K[(i+3) mod 8] shr 16)] xor
             C6[byte(K[(i+2) mod 8] shr  8)] xor
             C7[byte(K[(i+1) mod 8])]

    L[0] = L[0] xor RC[r]

    for i in 0..<8:
      K[i] = L[i]

    # apply r-th round transformation
    for i in 0..<8:
      L[i] = C0[byte(state[ i    mod 8] shr 56)] xor
             C1[byte(state[(i+7) mod 8] shr 48)] xor
             C2[byte(state[(i+6) mod 8] shr 40)] xor
             C3[byte(state[(i+5) mod 8] shr 32)] xor
             C4[byte(state[(i+4) mod 8] shr 24)] xor
             C5[byte(state[(i+3) mod 8] shr 16)] xor
             C6[byte(state[(i+2) mod 8] shr  8)] xor
             C7[byte(state[(i+1) mod 8])] xor
             K[i mod 8]

    for i in 0..<8:
      state[i] = L[i]

  # apply the Miyaguchi-Preneel compression function
  for i in 0..<8:
    w.hash[i] = w.hash[i] xor (state[i] xor blk[i])

proc write*(w: var Whirlpool, src: openarray[byte]) =
  var
    sourcePos: int                                              # index of the leftmost source
    nn: int = len(src)                                          # num of bytes to process
    sourceBits: uint64 = uint64(nn*8)                           # num of bits to process
    sourceGap: uint = uint((8 - (int(sourceBits and 7))) and 7) # space of src[sourcePos]
    bufferRem: uint = uint(w.bufferBits and 7)                  # occupied bits on buffer[bufferPos]
    b: uint32                                                   # current byte

  # tally the length of the data added
  var (i, carry, value) = (31, 0'u32, uint64(sourceBits))
  while(i >= 0 and (carry != 0 or value != 0)):
    carry += uint32(w.bitLength[i]) + (uint32(value) and 0xff)
    w.bitLength[i] = byte(carry)
    carry = carry shr 8
    value = value shr 8
    dec(i)

  # process data in chunks of 8 bits
  while(sourceBits > 8'u64):
    # take a byte from the source
    b = uint32((uint(src[sourcePos]) shl sourceGap) and 0xff) or
        ((src[sourcePos+1] and 0xff) shr (8'u64 - sourceGap))

    # process this byte
    w.buffer[w.bufferPos] = w.buffer[w.bufferPos] or uint8(b shr uint32(bufferRem))
    inc(w.bufferPos)
    w.bufferBits += int(8'u64 - bufferRem)

    if w.bufferBits == DigestBits:
      # process this block
      w.transform()
      # reset the buffer
      w.bufferBits = 0
      w.bufferPos = 0

    w.buffer[w.bufferPos] = byte(b shl uint32(8'u64 - bufferRem))
    w.bufferBits += int(bufferRem)

    # proceed to remaining data
    sourceBits -= 8
    inc(sourcePos)

  # 0 <= sourceBits <= 8; all data left over is in source[sourcePos]
  if sourceBits > 0'u64:
    b = uint32(((uint(src[sourcePos]) shl sourceGap)) and 0xff) # the bits are left-justified
    # process the remaining bits
    w.buffer[w.bufferPos] = w.buffer[w.bufferPos] or byte(b shr uint32(bufferRem))
  else:
    b = 0

  if uint64(bufferRem) + sourceBits < 8'u64:
    # the remaining data fits on the buffer[bufferPos]
    w.bufferBits += int(sourceBits)
  else:
    # the buffer[bufferPos] is full
    inc(w.bufferPos)
    w.bufferBits += int(8'u64 - bufferRem) # bufferBits = 8*bufferPos
    sourceBits -= uint64(8'u64 - bufferRem)

    # now, 0 <= sourceBits <= 8; all data left over is in source[sourcePos]
    if w.bufferBits == DigestBits:
      # process this data block
      w.transform()
      # reset buffer
      w.bufferBits = 0
      w.bufferPos = 0

    w.buffer[w.bufferPos] = byte(b shl uint32(8'u64 - bufferRem))
    w.bufferBits += int(sourceBits)

proc write*(w: var Whirlpool, s = "") =
  var bytes = newSeq[byte]()
  for c in s:
    bytes.add(byte(c))
  w.write(bytes)

proc sum*(w: Whirlpool, data: seq[byte] = nil): seq[byte] =
  # copy the whirlpool so that the caller doesn't need to be var
  var n = w

  # append a 1-bit
  n.buffer[n.bufferPos] = n.buffer[n.bufferPos] or byte(0x80'u64 shr (n.bufferBits and 7))
  inc(n.bufferPos)

  # the remaining bits should be 0. pad with zeros to be complete
  if n.bufferPos > (WBlockBytes-LengthBytes):
    if n.bufferPos < WBlockBytes:
      for i in 0..<(WBlockBytes-n.bufferPos):
        n.buffer[n.bufferPos+i] = 0
    # process this data block
    n.transform()
    # reset the buffer
    n.bufferPos = 0

  if n.bufferPos < (WBlockBytes-LengthBytes):
    for i in 0..<((WBlockBytes-LengthBytes)-n.bufferPos):
      n.buffer[n.bufferPos+i] = 0
  n.bufferPos = WBlockBytes-LengthBytes

  # append the bit length of the hashed data
  for i in 0..<LengthBytes:
    n.buffer[n.bufferPos+i] = n.bitLength[i]

  # process this data block
  n.transform()

  # return the final digest as a byte sequence
  var digest = newSeq[byte](DigestBytes)
  for i in 0..<(DigestBytes div 8):
    digest[i*8+0] = byte(n.hash[i] shr 56)
    digest[i*8+1] = byte(n.hash[i] shr 48)
    digest[i*8+2] = byte(n.hash[i] shr 40)
    digest[i*8+3] = byte(n.hash[i] shr 32)
    digest[i*8+4] = byte(n.hash[i] shr 24)
    digest[i*8+5] = byte(n.hash[i] shr 16)
    digest[i*8+6] = byte(n.hash[i] shr 08)
    digest[i*8+7] = byte(n.hash[i])

  result = data & digest[0..DigestBytes-1]

proc `$`*(w: Whirlpool): string =
  var m = w
  var res = m.sum()
  result = ""
  for c in res:
    result.add(toLower(toHex(ord(c), 2)))

proc initWhirlpool*(s = ""): Whirlpool =
  result.reset()
  if s != nil:
    result.write(s)

when isMainModule:
  var w = initWhirlpool()
  assert($w == "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7" &
    "a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3")
  w.write("I wouldn't marry him with a ten foot pole.")
  assert($w == "761d7db6292384ccc4a806a18404031d89dbbce5c22bb284a1e5d5979f44e3" &
    "7348857e555babf61b7eacbdc8df543f6477a5611330866d6660ed7c62655a5555")