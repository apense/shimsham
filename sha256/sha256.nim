import strtabs, strutils

const
  BlockSize = 64
  DigestSize = 32

type
  ShaObject = object {.inheritable.}
    digest*: array[8, int]
    countLo*: int
    countHi*: int
    data*: array[BlockSize, char]
    local*: int
    digestSize*: int

type 
  Sha256* = object of ShaObject
    sha*: ShaObject
    ds*, bs*: int
  Sha224* = object of Sha256

template ROR(x,y): expr =
  (((x and 0xffffffff) shr (y and 31)) or
    (x shl (32 - (y and 31)))) and 0xffffffff

template Ch(x,y,z): expr =
  (z xor (x and (y xor z)))

template Maj(x,y,z): expr =
  (((x or y) and z) or (x and y))

template S(x, n): expr =
  ROR(x, n)

template R(x, n): expr = 
  (x and 0xffffffff) shr n

template Sigma0(x): expr =
  (S(x, 2) xor S(x, 13) xor S(x, 22))

template Simga1(x): expr =
  (S(x, 6) xor S(x, 11) xor S(x, 25))

template Gamma0(x): expr =
  (S(x, 7) xor S(x, 18) xor R(x, 3))

template Gamma1(x): expr =
  (S(x, 17) xor S(x, 19) xor R(x, 10))

proc shaInit(): ShaObject =
  result.digest = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
  result.countLo = 0
  result.countHi = 0
  result.local = 0
  result.digestSize = 32

proc sha224Init(): ShaObject =
  result.digest = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
    0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4]
  result.countLo = 0
  result.countHi = 0
  result.local = 0
  result.digestSize = 28

proc shaTransform(shaInfo: var ShaObject) =
  var W = newSeq[int]()

  var d = shaInfo.data
  for i in 0..15:
    let m = (ord(d[4*i]) shl 24) + (ord(d[4*i+1]) shl 16) + (ord(d[4*i+2]) shl 8) + ord(d[4*i+3])
    W.add(m)

  for i in 16..63:
    W.add((Gamma1(W[i-2]) + W[i-7] + Gamma0(W[i-15]) + W[i-16]) and 0xffffffff)

  var ss = shaInfo.digest

  proc RND(a, b, c: int, d: var int, e, f, g: int, h: var int, i, ki: int): tuple[d, h: int] =
    var t0 = h + Simga1(e) + Ch(e, f, g) + ki + W[i]
    var t1 = Sigma0(a) + Maj(a, b, c)
    d += t0
    h = t0 + t1
    result = (d and 0xffffffff, h and 0xffffffff)

  var res = RND(ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],0,0x428a2f98)
  ss[3] = res.d
  ss[7] = res.h
  res = RND(ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],1,0x71374491)
  ss[2] = res.d
  ss[6] = res.h
  res = RND(ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],2,0xb5c0fbcf)
  ss[1] = res.d
  ss[5] = res.h
  res = RND(ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],3,0xe9b5dba5)
  ss[0] = res.d
  ss[4] = res.h
  res = RND(ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],4,0x3956c25b)
  ss[7] = res.d
  ss[3] = res.h
  res = RND(ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],5,0x59f111f1)
  ss[6] = res.d
  ss[2] = res.h
  res = RND(ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],6,0x923f82a4)
  ss[5] = res.d
  ss[1] = res.h
  res = RND(ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],7,0xab1c5ed5)
  ss[4] = res.d
  ss[0] = res.h
  res = RND(ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],8,0xd807aa98)
  ss[3] = res.d
  ss[7] = res.h
  res = RND(ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],9,0x12835b01)
  ss[2] = res.d
  ss[6] = res.h
  res = RND(ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],10,0x243185be)
  ss[1] = res.d
  ss[5] = res.h
  res = RND(ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],11,0x550c7dc3)
  ss[0] = res.d
  ss[4] = res.h
  res = RND(ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],12,0x72be5d74)
  ss[7] = res.d
  ss[3] = res.h
  res = RND(ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],13,0x80deb1fe)
  ss[6] = res.d
  ss[2] = res.h
  res = RND(ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],14,0x9bdc06a7)
  ss[5] = res.d
  ss[1] = res.h
  res = RND(ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],15,0xc19bf174)
  ss[4] = res.d
  ss[0] = res.h
  res = RND(ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],16,0xe49b69c1)
  ss[3] = res.d
  ss[7] = res.h
  res = RND(ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],17,0xefbe4786)
  ss[2] = res.d
  ss[6] = res.h
  res = RND(ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],18,0x0fc19dc6)
  ss[1] = res.d
  ss[5] = res.h
  res = RND(ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],19,0x240ca1cc)
  ss[0] = res.d
  ss[4] = res.h
  res = RND(ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],20,0x2de92c6f)
  ss[7] = res.d
  ss[3] = res.h
  res = RND(ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],21,0x4a7484aa)
  ss[6] = res.d
  ss[2] = res.h
  res = RND(ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],22,0x5cb0a9dc)
  ss[5] = res.d
  ss[1] = res.h
  res = RND(ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],23,0x76f988da)
  ss[4] = res.d
  ss[0] = res.h
  res = RND(ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],24,0x983e5152)
  ss[3] = res.d
  ss[7] = res.h
  res = RND(ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],25,0xa831c66d)
  ss[2] = res.d
  ss[6] = res.h
  res = RND(ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],26,0xb00327c8)
  ss[1] = res.d
  ss[5] = res.h
  res = RND(ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],27,0xbf597fc7)
  ss[0] = res.d
  ss[4] = res.h
  res = RND(ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],28,0xc6e00bf3)
  ss[7] = res.d
  ss[3] = res.h
  res = RND(ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],29,0xd5a79147)
  ss[6] = res.d
  ss[2] = res.h
  res = RND(ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],30,0x06ca6351)
  ss[5] = res.d
  ss[1] = res.h
  res = RND(ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],31,0x14292967)
  ss[4] = res.d
  ss[0] = res.h
  res = RND(ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],32,0x27b70a85)
  ss[3] = res.d
  ss[7] = res.h
  res = RND(ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],33,0x2e1b2138)
  ss[2] = res.d
  ss[6] = res.h
  res = RND(ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],34,0x4d2c6dfc)
  ss[1] = res.d
  ss[5] = res.h
  res = RND(ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],35,0x53380d13)
  ss[0] = res.d
  ss[4] = res.h
  res = RND(ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],36,0x650a7354)
  ss[7] = res.d
  ss[3] = res.h
  res = RND(ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],37,0x766a0abb)
  ss[6] = res.d
  ss[2] = res.h
  res = RND(ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],38,0x81c2c92e)
  ss[5] = res.d
  ss[1] = res.h
  res = RND(ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],39,0x92722c85)
  ss[4] = res.d
  ss[0] = res.h
  res = RND(ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],40,0xa2bfe8a1)
  ss[3] = res.d
  ss[7] = res.h
  res = RND(ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],41,0xa81a664b)
  ss[2] = res.d
  ss[6] = res.h
  res = RND(ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],42,0xc24b8b70)
  ss[1] = res.d
  ss[5] = res.h
  res = RND(ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],43,0xc76c51a3)
  ss[0] = res.d
  ss[4] = res.h
  res = RND(ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],44,0xd192e819)
  ss[7] = res.d
  ss[3] = res.h
  res = RND(ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],45,0xd6990624)
  ss[6] = res.d
  ss[2] = res.h
  res = RND(ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],46,0xf40e3585)
  ss[5] = res.d
  ss[1] = res.h
  res = RND(ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],47,0x106aa070)
  ss[4] = res.d
  ss[0] = res.h
  res = RND(ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],48,0x19a4c116)
  ss[3] = res.d
  ss[7] = res.h
  res = RND(ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],49,0x1e376c08)
  ss[2] = res.d
  ss[6] = res.h
  res = RND(ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],50,0x2748774c)
  ss[1] = res.d
  ss[5] = res.h
  res = RND(ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],51,0x34b0bcb5)
  ss[0] = res.d
  ss[4] = res.h
  res = RND(ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],52,0x391c0cb3)
  ss[7] = res.d
  ss[3] = res.h
  res = RND(ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],53,0x4ed8aa4a)
  ss[6] = res.d
  ss[2] = res.h
  res = RND(ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],54,0x5b9cca4f)
  ss[5] = res.d
  ss[1] = res.h
  res = RND(ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],55,0x682e6ff3)
  ss[4] = res.d
  ss[0] = res.h
  res = RND(ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],56,0x748f82ee)
  ss[3] = res.d
  ss[7] = res.h
  res = RND(ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],57,0x78a5636f)
  ss[2] = res.d
  ss[6] = res.h
  res = RND(ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],58,0x84c87814)
  ss[1] = res.d
  ss[5] = res.h
  res = RND(ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],59,0x8cc70208)
  ss[0] = res.d
  ss[4] = res.h
  res = RND(ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],60,0x90befffa)
  ss[7] = res.d
  ss[3] = res.h
  res = RND(ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],61,0xa4506ceb)
  ss[6] = res.d
  ss[2] = res.h
  res = RND(ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],62,0xbef9a3f7)
  ss[5] = res.d
  ss[1] = res.h
  res = RND(ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],63,0xc67178f2)
  ss[4] = res.d
  ss[0] = res.h

  var dig: array[8, int]
  for i,x in shaInfo.digest:
    dig[i] = ((x + ss[i]) and 0xffffffff)
  shaInfo.digest = dig

proc shaUpdate(shaInfo: var ShaObject, buffer: seq[char]) =
  var count = len(buffer)
  var bufferIdx = 0
  var clo = (shaInfo.countLo + (count shl 3)) and 0xffffffff
  if(clo < shaInfo.countLo):
    inc(shaInfo.countHi)
  shaInfo.countLo = clo

  shaInfo.countHi += (count shr 29)

  if(shaInfo.local != 0):
    var i = BlockSize - shaInfo.local
    if(i > count):
      i = count

    # copy buffer
    for i,b in buffer[bufferIdx..bufferIdx+i-1]:
      shaInfo.data[shaInfo.local + i] = b

    count -= i
    bufferIdx += i

    shaInfo.local += i
    if(shaInfo.local == BlockSize):
      shaTransform(shaInfo)
      shaInfo.local = 0
    else:
      return

  while(count >= BlockSize):
    # copy buffer
    for i,b in buffer[bufferIdx..bufferIdx+BlockSize-1]:
      shaInfo.data[i] = b
    count -= BlockSize
    bufferIdx += BlockSize
    shaTransform(shaInfo)

  # copy buffer
  var pos = shaInfo.local
  for i,b in buffer[bufferIdx..bufferIdx+count-1]:
    shaInfo.data[pos+i] = b
  shaInfo.local = count

proc shaFinal(shaInfo: var ShaObject): string =
  var (loBitCount, hiBitCount) = (shaInfo.countLo, shaInfo.countHi)

  var count = (loBitCount shr 3) and 0x3f
  shaInfo.data[count] = chr(0x80)
  inc(count)

  if count > BlockSize - 8:
    # zero the bytes in data after the count
    for i in count..BlockSize-1:
      shaInfo.data[i] = chr(0)
    shaTransform(shaInfo)
    # zero bytes in data
    for i,b in shaInfo.data:
      shaInfo.data[i] = chr(0)
  else:
    for i in count..BlockSize-1:
      shaInfo.data[i] = chr(0)

  shaInfo.data[56] = chr((hiBitCount shr 24) and 0xff)
  shaInfo.data[57] = chr((hiBitCount shr 16) and 0xff)
  shaInfo.data[58] = chr((hiBitCount shr  8) and 0xff)
  shaInfo.data[59] = chr((hiBitCount shr  0) and 0xff)
  shaInfo.data[60] = chr((loBitCount shr 24) and 0xff)
  shaInfo.data[61] = chr((loBitCount shr 16) and 0xff)
  shaInfo.data[62] = chr((loBitCount shr  8) and 0xff)
  shaInfo.data[63] = chr((loBitCount shr  0) and 0xff)

  shaTransform(shaInfo)

  var dig = newSeq[char]()
  for i in shaInfo.digest:
    dig = dig & @[chr((i shr 24) and 0xff), chr((i shr 16) and 0xff), chr((i shr 8) and 0xff), chr(i and 0xff)]

  var res = ""
  for i in dig:
    res.add(i)

  result = res

proc initSha256*(s = ""): Sha256 =
  result.ds = DigestSize
  result.bs = BlockSize
  result.sha = shaInit()
  var buf = newSeq[char]()
  if s != nil:
    for c in s:
      buf.add(c)
    shaUpdate(result.sha, buf)

proc initSha224*(s = ""): Sha224 =
  result.ds = 28
  result.bs = BlockSize
  result.sha = sha224Init()
  var buf = newSeq[char]()
  if s != nil:
    for c in s:
      buf.add(c)
    shaUpdate(result.sha, buf)

proc update*(s: var Sha256, sc: seq[char]) =
  shaUpdate(s.sha, sc)

proc update*(s: var Sha256, str: string) =
  var buf = newSeq[char]()
  for c in str:
    buf.add(c)
  shaUpdate(s.sha, buf)

proc strDigest(s: var Sha256): string =
  result = shaFinal(s.sha)[0..s.sha.digestSize-1]

proc hexDigest(s: var Sha256): string =
  var dig = s.strDigest
  result = ""
  for i in dig:
    result.add(toLower(toHex(ord(i), 2)))

proc hexDigest*(s: Sha256): string =
  var m = s
  result = m.hexDigest

proc `$`*(s: Sha256): string =
  result = s.hexDigest

proc `$`*(s: Sha224): string =
  result = s.hexDigest

proc sha256*(s = ""): string =
  result = initSha256(s).hexDigest

proc sha224*(s = ""): string =
  result = initSha224(s).hexDigest

when isMainModule:
  var s = initSha256()
  let astr = "just a test string"
  
  assert(s.hexDigest == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
  s = initSha256("just a test string")
  assert(s.hexDigest == "d7b553c6f09ac85d142415f857c5310f3bbbe7cdd787cce4b985acedd585266f")
  s = initSha256(astr)
  s.update(astr)
  assert(s.hexDigest == "03d9963e05a094593190b6fc794cb1a3e1ac7d7883f0b5855268afeccc70d461")
  assert(sha224() == "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f")
