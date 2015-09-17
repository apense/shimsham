import strutils
import tables

const
  Rows = 8
  LengthFieldLen = Rows
  Cols512 = 8
  Cols1024 = 15
  Size512 = Rows*Cols512
  Size1024 = Rows*Cols1024

  Rounds512 = 10
  Rounds1024 = 14

template rotl64(a,n): int =
  ((((a)shl(n))or((a)shr(64-(n))))and(0xffffffffffffffff))

when cpuEndian == bigEndian:
  template extByte(va, n) =
    (va.uint64 shr (8*(7-n)))
  template u64big(a) = a
else:
  template extByte(va, n): int =
    (va.int shr (8*n))
  template u64big(a): int =
    (rotl64(a,  8) and 0x000000ff000000ff) or
      (rotl64(a, 24) and 0x0000ff000000ff00) or
      (rotl64(a, 40) and 0x00ff000000ff0000) or
      (rotl64(a, 56) and 0xff000000ff000000)

const
  Long = Size1024
  Short = Size512

# begin NIST API
type
  BitSequence = byte
  DataLength = BiggestInt
  HashReturn = enum
    Success
    Fail
    BadHashlen

type
  HashState = object
    chaining: seq[int] ## actual state
    buffer: seq[BitSequence] ## data buffer
    blockCounter: int ## message block counter
    bufptr: int ## data buffer location
    bitsinlastbyte: int ## no. of message bits in last byte of buffer
    hashbitlen: int ## output length in bits
    size: int ## Long or Short

proc printstate(y: openarray[int]) =
  assert y.len == Cols512
  for i in 0..<Cols512:
    echo toHex(y[i],3)
  echo "\n"

template column(x,y,i,c0,c1,c2,c3,c4,c5,c6,c7) =
  y[i] = T[0*256+extByte(x[c0],0)] xor
         T[1*256+extByte(x[c1],1)] xor
         T[2*256+extByte(x[c2],2)] xor
         T[3*256+extByte(x[c3],3)] xor
         T[4*256+extByte(x[c4],4)] xor
         T[5*256+extByte(x[c5],5)] xor
         T[6*256+extByte(x[c6],6)] xor
         T[7*256+extByte(x[c7],7)]

template rnd512p(x,y,r) =
  ## compute a round in P
  x[0] = x[0] xor (0x0000000000000000) xor r
  x[1] = x[1] xor (0x1000000000000000) xor r
  x[2] = x[2] xor (0x2000000000000000) xor r
  x[3] = x[3] xor (0x3000000000000000) xor r
  x[4] = x[4] xor (0x4000000000000000) xor r
  x[5] = x[5] xor (0x5000000000000000) xor r
  x[6] = x[6] xor (0x6000000000000000) xor r
  x[7] = x[7] xor (0x7000000000000000) xor r
  column(x,y,0,0,1,2,3,4,5,6,7)
  column(x,y,1,1,2,3,4,5,6,7,0)
  column(x,y,2,2,3,4,5,6,7,0,1)
  column(x,y,3,3,4,5,6,7,0,1,2)
  column(x,y,4,4,5,6,7,0,1,2,3)
  column(x,y,5,5,6,7,0,1,2,3,4)
  column(x,y,6,6,7,0,1,2,3,4,5)
  column(x,y,7,7,0,1,2,3,4,5,6)

template rnd512q(x,y,r) =
  x[0] = x[0] xor (0xffffffffffffffff) xor r
  x[1] = x[1] xor (0xffffffffffffffef) xor r
  x[2] = x[2] xor (0xffffffffffffffdf) xor r
  x[3] = x[3] xor (0xffffffffffffffcf) xor r
  x[4] = x[4] xor (0xffffffffffffffbf) xor r
  x[5] = x[5] xor (0xffffffffffffffaf) xor r
  x[6] = x[6] xor (0xffffffffffffff9f) xor r
  x[7] = x[7] xor (0xffffffffffffff8f) xor r
  column(x,y,0,1,3,5,7,0,2,4,6)
  column(x,y,1,2,4,6,0,1,3,5,7)
  column(x,y,2,3,5,7,1,2,4,6,0)
  column(x,y,3,4,6,0,2,3,5,7,1)
  column(x,y,4,5,7,1,3,4,6,0,2)
  column(x,y,5,6,0,2,4,5,7,1,3)
  column(x,y,6,7,1,3,5,6,0,2,4)
  column(x,y,7,0,2,4,6,7,1,3,5)

template rnd1024p(x,y,r) =
  ## compute a round in P
  x[ 0] = x[ 0] xor (0x0000000000000000) xor r
  x[ 1] = x[ 1] xor (0x1000000000000000) xor r
  x[ 2] = x[ 2] xor (0x2000000000000000) xor r
  x[ 3] = x[ 3] xor (0x3000000000000000) xor r
  x[ 4] = x[ 4] xor (0x4000000000000000) xor r
  x[ 5] = x[ 5] xor (0x5000000000000000) xor r
  x[ 6] = x[ 6] xor (0x6000000000000000) xor r
  x[ 7] = x[ 7] xor (0x7000000000000000) xor r
  x[ 8] = x[ 8] xor (0x8000000000000000) xor r
  x[ 9] = x[ 9] xor (0x9000000000000000) xor r
  x[10] = x[10] xor (0xa000000000000000) xor r
  x[11] = x[11] xor (0xb000000000000000) xor r
  x[12] = x[12] xor (0xc000000000000000) xor r
  x[13] = x[13] xor (0xd000000000000000) xor r
  x[14] = x[14] xor (0xe000000000000000) xor r
  x[15] = x[15] xor (0xf000000000000000) xor r
  column(x,y,15,15, 0, 1, 2, 3, 4, 5, 10)
  column(x,y,14,14,15, 0, 1, 2, 3, 4,  9)
  column(x,y,13,13,14,15, 0, 1, 2, 3,  8)
  column(x,y,12,12,13,14,15, 0, 1, 2,  7)
  column(x,y,11,11,12,13,14,15, 0, 1,  6)
  column(x,y,10,10,11,12,13,14,15, 0,  5)
  column(x,y, 9, 9,10,11,12,13,14,15,  4)
  column(x,y, 8, 8, 9,10,11,12,13,14,  3)
  column(x,y, 7, 7, 8, 9,10,11,12,13,  2)
  column(x,y, 6, 6, 7, 8, 9,10,11,12,  1)
  column(x,y, 5, 5, 6, 7, 8, 9,10,11,  0)
  column(x,y, 4, 4, 5, 6, 7, 8, 9,10, 15)
  column(x,y, 3, 3, 4, 5, 6, 7, 8, 9, 14)
  column(x,y, 2, 2, 3, 4, 5, 6, 7, 8, 13)
  column(x,y, 1, 1, 2, 3, 4, 5, 6, 7, 12)
  column(x,y, 0, 0, 1, 2, 3, 4, 5, 6, 11)

template rnd1024q(x,y,r) =
  x[ 0] = x[ 0] xor (0xffffffffffffffff) xor r
  x[ 1] = x[ 1] xor (0xffffffffffffffef) xor r
  x[ 2] = x[ 2] xor (0xffffffffffffffdf) xor r
  x[ 3] = x[ 3] xor (0xffffffffffffffcf) xor r
  x[ 4] = x[ 4] xor (0xffffffffffffffbf) xor r
  x[ 5] = x[ 5] xor (0xffffffffffffffaf) xor r
  x[ 6] = x[ 6] xor (0xffffffffffffff9f) xor r
  x[ 7] = x[ 7] xor (0xffffffffffffff8f) xor r
  x[ 8] = x[ 8] xor (0xffffffffffffff7f) xor r
  x[ 9] = x[ 9] xor (0xffffffffffffff6f) xor r
  x[10] = x[10] xor (0xffffffffffffff5f) xor r
  x[11] = x[11] xor (0xffffffffffffff4f) xor r
  x[12] = x[12] xor (0xffffffffffffff3f) xor r
  x[13] = x[13] xor (0xffffffffffffff2f) xor r
  x[14] = x[14] xor (0xffffffffffffff1f) xor r
  x[15] = x[15] xor (0xffffffffffffff0f) xor r
  column(x,y,15, 0, 2, 4,10,15, 1, 3, 5)
  column(x,y,14,15, 1, 3, 9,14, 0, 2, 4)
  column(x,y,13,14, 0, 2, 8,13,15, 1, 3)
  column(x,y,12,13,15, 1, 7,12,14, 0, 2)
  column(x,y,11,12,14, 0, 6,11,13,15, 1)
  column(x,y,10,11,13,15, 5,10,12,14, 0)
  column(x,y, 9,10,12,14, 4, 9,11,13,15)
  column(x,y, 8, 9,11,13, 3, 8,10,12,14)
  column(x,y, 7, 8,10,12, 2, 7, 9,11,13)
  column(x,y, 6, 7, 9,11, 1, 6, 8,10,12)
  column(x,y, 5, 6, 8,10, 0, 5, 7, 9,11)
  column(x,y, 4, 5, 7, 9,15, 4, 6, 8,10)
  column(x,y, 3, 4, 6, 8,14, 3, 5, 7, 9)
  column(x,y, 2, 3, 5, 7,13, 2, 4, 6, 8)
  column(x,y, 1, 2, 4, 6,12, 1, 3, 5, 7)
  column(x,y, 0, 1, 3, 5,11, 0, 2, 4, 6)

proc f512(h: var seq[int], m: seq[int]) =
  var
    y = newSeq[int](Cols512)
    z = newSeq[int](Cols512)
    outq = newSeq[int](Cols512)
    inp = newSeq[int](Cols512)

  for i in 0..<Cols512:
    z[i] = m[i]
    inp[i] = h[i] xor m[i]

  # compute Q(m)
  rnd512q(z,y,0x0000000000000000)
  rnd512q(y,z,0x0000000000000001)
  rnd512q(z,y,0x0000000000000002)
  rnd512q(y,z,0x0000000000000003)
  rnd512q(z,y,0x0000000000000004)
  rnd512q(y,z,0x0000000000000005)
  rnd512q(z,y,0x0000000000000006)
  rnd512q(y,z,0x0000000000000007)
  rnd512q(z,y,0x0000000000000008)
  rnd512q(y,outq,0x0000000000000009)

  # computer P(h+m)
  rnd512p(inp,z,0x0000000000000000)
  rnd512p(z,y,0x0100000000000000)
  rnd512p(y,z,0x0200000000000000)
  rnd512p(z,y,0x0300000000000000)
  rnd512p(y,z,0x0400000000000000)
  rnd512p(z,y,0x0500000000000000)
  rnd512p(y,z,0x0600000000000000)
  rnd512p(z,y,0x0700000000000000)
  rnd512p(y,z,0x0800000000000000)
  rnd512p(z,y,0x0900000000000000)

  # h' == h + Q(m) + P(h+m)
  for i in 0..Cols512:
    h[i] = h[i] xor outq[i] xor y[i]

proc f1024(h: var seq[int], m: seq[int]) =
  var
    y = newSeq[int](Cols1024)
    z = newSeq[int](Cols1024)
    outq = newSeq[int](Cols1024)
    inp = newSeq[int](Cols1024)

  for i in 0..<Cols1024:
    z[i] = m[i]
    inp[i] = h[i] xor m[i]

  # compute Q(m)
  rnd1024q(z,y,0)
  for i in countup(1, Rounds1024-2, 2):
    z[i] = m[i]
    inp[i] = h[i] xor m[i]
  rnd1024q(y,outq, Rounds1024-1)

  # computer P(h+m)
  rnd1024p(inp,z,0)
  for i in countup(1, Rounds1024-2, 2):
    rnd1024p(z,y,i shl 56)
    rnd1024p(y,z,(i+1) shl 56)
  rnd1024p(z,y,(Rounds1024-1) shl 56)

  # h' == h + Q(m) + P(h+m)
  for i in 0..Cols1024:
    h[i] = h[i] xor outq[i] xor y[i]

proc transform(hs: var HashState, input: openarray[byte], msglen: int) =
  ## digest up to `msglen` bytes of input (full blocks only)

  # determine variant and select compression function
  var msglen = msglen
  var pos = 0
  if hs.size == Short:
    # increment block counter
    hs.blockCounter += msglen div Size512
    while msglen >= Size512:
      f512(hs.chaining, cast[seq[int]](input[pos..^1]))
      msglen -= Size512
      pos += Size512
  else:
    # increment block counter
    hs.blockCounter += msglen div Size1024
    while msglen >= Size1024:
      f1024(hs.chaining, cast[seq[int]](input[pos..^1]))
      msglen -= Size1024
      pos += Size1024