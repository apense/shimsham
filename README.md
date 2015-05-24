ShimSham
========

ShimSham is a Nim module to encompass several different digest/hashing algorithms. So far included are [Sha2](https://en.wikipedia.org/wiki/SHA-2), [Tiger](https://en.wikipedia.org/wiki/Tiger_%28cryptography%29), and [Whirlpool](https://en.wikipedia.org/wiki/Whirlpool_%28cryptography%29). Hopefully there will be some more soon.

Unfortunately, there isn't a common access interface yet. A fuller README and some usage examples will come soon.

For Sha256 (of SHA-2), try:

```nim
import sha256

var message = "My message to hash"
var m = initSha256(message) ## initializes and `Sha256` object with `message`
echo m ## gives "aefd1872a4eb24a79a1e727aa8c41ebde794451c0ca89a0e3abe82e45a477afc"
```
You can also use `initSha224` if that's what you want.

`initSha384` and `initSha512` are available in the sha512 module.

`initWhirlpool` works in the same way.

For the Tiger hash, here's how you call:
```nim
import tiger

echo tiger("") ## gives "24f0130c63ac933216166e76b1bb925ff373de2d49584e7a"
```

The Tiger hash way seems cleaner, and all functions might switch to that soon.