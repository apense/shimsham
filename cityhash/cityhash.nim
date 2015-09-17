include cityutils

const
  k0 = 0xc3a5c85c97cb3127u64
  k1 = 0xb492b66fbe98f273u64
  k2 = 0x9ae16a3b2f90404fu64

  c1 = 0xcc9e2d51
  c2 = 0x1b873593



proc fmix(h: uint32): uint32 =
  var n = h
  n = n xor (n shr 16)
  n = n * 0x85ebca6b
  n = n xor (n shr 13)
  n = n * 0xc2b2ae35
  result = n

proc rotate32(val: uint32, shift: int): uint32 =
  var shift = shift.uint32
  result = if shift == 0: val 
        else: ((val shr shift) or (val shl (32u32 - shift)))

proc permute3(a, b, c: var any) {.inline.} =
  swap(a, b)
  swap(a, c)

proc mur(a, h: uint32): uint32 =
  var (a, h) = (a, h)
  a = a * c1
  a = rotate32(a, 17)
  a = a * c2
  h = h xor a
  h = rotate32(h, 19)
  result = h * 5 + 0xe6546b64


proc hash32Len13To24(s: string, len: int): uint32 =
  var
    a = fetch32(s[((len shr 1) - 4) .. ^1])
    b = fetch32(s[4..^1])
    c = fetch32(s[(len - 8)..^1])
    d = fetch32(s[(len shr 1)..^1])
    e = fetch32(s)
    f = fetch32(s[(len - 4)..^1])
    h = len.uint32

  result = fmix(mur(f, mur(e, mur(d, mur(c, mur(b, mur(a,h)))))))
