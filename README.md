# py-multihash

Multihash implementation in Python with a low level API and two hashlib compatible APIs: a strict drop-in replacement one and an extended one with utility methods.

```
multihash
├──__init__.py 
├── multihash.py      # based on tehmaze's low level multihash packing library
├── multihashlib.py   # based on JulienPalard's hashlib-compatible, extended with verify(), truncation, etc.
├── hashlib.py        # multihashlib, restricted a cloned API of stdlib's hashlib, no extensions.
└── utils.py          # wraps all external dependencies so they can be switched out more easily
```





