import unsigned
import strutils

const
  BlockBytes*: uint = 128
  OutBytes*: uint   = 64
  KeyBytes*: uint   = 64

const
  Sigma: array[12, array[16, byte]] = [
    [  0.byte,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ],
    [ 14.byte, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 ],
    [ 11.byte,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 ],
    [  7.byte,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 ],
    [  9.byte,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 ],
    [  2.byte, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 ],
    [ 12.byte,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 ],
    [ 13.byte, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 ],
    [  6.byte, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 ],
    [ 10.byte,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 ],
    [  0.byte,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ],
    [ 14.byte, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 ],
  ]

const
  IV: array[8, uint64] = [
    0x6a09e667f3bcc908'u64, 0xbb67ae8584caa73b'u64, 0x3c6ef372fe94f82b'u64, 0xa54ff53a5f1d36f1'u64,
    0x510e527fade682d1'u64, 0x9b05688c2b3e6c1f'u64, 0x1f83d9abfb41bd6b'u64, 0x5be0cd19137e2179'u64,
  ]

type
  Blake2b* = object
    h: array[8, uint64]
    t: array[2, uint64]
    f: array[2, uint64]
    buf: array[2*BlockBytes.int, uint8]
    bufLen: uint

proc load64(b: openarray[byte]): uint64 =
  var v = 0'u64
  for i in 0..<8:
    v = v or (b[i].uint64) shl (8*i).uint64

proc store64(b: var openarray[byte], v: uint64) =
  var w = v
  for i in 0..<8:
    b[i] = w.byte
    w = w shr 8
  #echo "b: ", @b

proc rotateRight(x, n: uint64): uint64 =
  result = (x shr n) or (x shl (64'u64 - n))

proc encodeParams(size: byte, keylen: byte): array[64, byte] =
  result[0] = size
  result[1] = keylen
  result[2] = 1 # fanout
  result[3] = 1 # depth

proc initBlake2b*(size: int): Blake2b =
  assert(size > 0 and size <= OutBytes.int)

  let param = encodeParams(size.byte, 0)
  var state = IV

  for i in 0..<state.len:
    state[i] = state[i] xor load64(param[i*8..^1])

  result = Blake2b(
      h: state,
      bufLen: 0
    )

proc incrementCounter(b: var Blake2b, inc: uint64) =
  b.t[0] += inc
  b.t[1] += (if b.t[0] < inc: 1 else: 0)

proc compress(b: var Blake2b) =
  var m = newSeq[uint64](16)
  var v = newSeq[uint64](16)
  #echo "b.h beginning: ", (@(b.h))

  assert(b.buf.len >= BlockBytes.int)

  for i in 0..<m.len:
    m[i] = load64(b.buf[i*4..^1])

  for i in 0..<8:
    v[i] = b.h[i]

  v[ 8] = IV[0]
  v[ 9] = IV[1]
  v[10] = IV[2]
  v[11] = IV[3]
  v[12] = b.t[0] xor IV[4]
  v[13] = b.t[1] xor IV[5]
  v[14] = b.f[0] xor IV[6]
  v[15] = b.f[1] xor IV[7]

  template g(r, i, a, b, c, d) =
    a = a + b + (m[Sigma[r][2*i+0].int])
    d = (d xor a).rotateRight(32)
    c = c + d
    b = (b xor c).rotateRight(24)
    a = a + b + (m[Sigma[r][2*i+1].int])
    d = (d xor a).rotateRight(16)
    c = c + d
    b = (b xor c).rotateRight(63)

  template round(r) =
    g(r, 0, v[ 0], v[ 4], v[ 8], v[12])
    g(r, 1, v[ 1], v[ 5], v[ 9], v[13])
    g(r, 2, v[ 2], v[ 6], v[10], v[14])
    g(r, 3, v[ 3], v[ 7], v[11], v[15])
    g(r, 4, v[ 0], v[ 5], v[10], v[15])
    g(r, 5, v[ 1], v[ 6], v[11], v[12])
    g(r, 6, v[ 2], v[ 7], v[ 8], v[13])
    g(r, 7, v[ 3], v[ 4], v[ 9], v[14])

  for i in 0..<12:
    round(i)

  for i in 0..<8:
    b.h[i] = b.h[i] xor v[i] xor v[i+8]
  #echo "b.h end: ", (@(b.h))

proc update*(b: var Blake2b, m: openarray[byte]) =
  var m = @m

  while m.len > 0:
    let left = b.bufLen.int
    let fill = 2*BlockBytes.int - left.int

    if m.len > fill:
      for i in 0..<fill:
        b.buf[left + i] = m[i]
      b.bufLen += fill.uint
      m = m[fill..^1]
      b.incrementCounter(BlockBytes.uint64)
      b.compress()
      for i in 0..<BlockBytes.int:
        b.buf[i] = b.buf[i+BlockBytes.int]
      b.bufLen -= BlockBytes
    else:
      for i in 0..<m.len:
        b.buf[left+i] = m[i]
      b.bufLen += m.len.uint
      m = m[m.len..^1]

proc finalize*(b: var Blake2b, output: var openarray[byte]) =
  var buf = newSeq[byte](OutBytes)
  if b.bufLen > BlockBytes:
    b.incrementCounter(BlockBytes.uint64)
    b.compress()
    for i in 0..<BlockBytes.int:
      b.buf[i] = b.buf[i+BlockBytes.int]
    b.bufLen -= BlockBytes

  let n = b.bufLen.uint64
  b.incrementCounter(n)
  b.f[0] = not 0'u64
  for i in b.bufLen..<b.buf.len:
    b.buf[i] = 0

  b.compress()


  for i in 0..<b.h.len:
    var tmpBuf = b.buf[i*8..^1]
    store64(tmpBuf, b.h[i])
    #echo "buf: ", buf[i]
    #echo "newBuf: ", newBuf[i*8..^1]
    #echo "buflen: ", buf.len
    #echo "newbuflen: ", tmpBuf.len
    #echo "hlen: ", b.h.len
    for j in 0..<8:
      #echo "j: ", j
      buf[i*8+j] = tmpBuf[j]

  for i in 0..<min(output.len, OutBytes.int):
    #echo "output length: ", output.len
    #echo "buf length: ", buf.len
    output[i] = buf[i]

proc initBlake2b*(size: int, key: openarray[byte]): Blake2b =
  assert(size > 0 and size <= OutBytes.int)
  assert(key.len > 0 and key.len <= KeyBytes.int)

  let param = encodeParams(size.byte, key.len.byte)
  var state = IV

  for i in 0..<state.len:
    state[i] = state[i] xor load64(param[i*8..^1])

  var b = Blake2b(
      h: state,
      bufLen: 0
    )

  var datablock: array[BlockBytes.int, byte]
  for i in 0..<key.len:
    datablock[i] = key[i]

  b.update(datablock)
  result = b

import unicode
proc stringToBytes(s: string): seq[byte] =
  result = cast[seq[byte]](s)

proc blake2bSeq*(key: string = ""): seq[byte] =
  var b = initBlake2b(OutBytes.int)
  b.update(key.stringToBytes)
  var outseq = newSeq[byte](OutBytes)
  b.finalize(outseq)
  result = outseq

proc blake2b*(key: string = ""): string = 
  var mseq = blake2bSeq(key)
  #echo "mseq: ", mseq
  result = ""
  for i in mseq:
    result.add(toHex(i.int, 2).toLower)

var s = "ĄąĲĳ\0"
echo blake2b("The quick brown fox jumps over the lazy dog")
echo blake2b()