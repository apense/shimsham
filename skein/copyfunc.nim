
proc copy*[T](a, b: var openarray[T]) =
  var n = min(len(a),len(b))
  copyMem(addr a, addr b, n * sizeof(a[0]))

proc copy*[T](a, b: openarray[T]) =
  var (a,b) = (@a,@b)
  var n = min(len(a),len(b))
  copyMem(addr a, addr b, n * sizeof(a[0]))
