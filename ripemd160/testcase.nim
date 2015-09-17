
proc test(j: int) =
  case j
  of <0:
    echo "invalid"
  of <15,15:
    echo "hello"
  else:
    discard

test(-1)