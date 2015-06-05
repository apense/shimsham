
proc wordToBytes(word: int, bytes: var openarray[byte], offset: int) =
  bytes[offset + 0] = word.byte
  bytes[offset + 1] = (word shr  8).byte
  bytes[offset + 2] = (word shr 16).byte
  bytes[offset + 3] = (word shr 24).byte
  bytes[offset + 4] = (word shr 32).byte
  bytes[offset + 5] = (word shr 40).byte
  bytes[offset + 6] = (word shr 48).byte
  bytes[offset + 7] = (word shr 56).byte