# BLS C wrapper

## How to use:

```bash
git submodule update --init --recursive
mkdir build
cd build
meson -Ddefault_library=both ..
ninja -j 16
```

The header is at `src/bls-wrapper.h`
