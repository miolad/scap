Build with:

```bash
# Use clang >= 15
CLANG_BIN=clang-15 cargo build --release
gcc examples-c/simple.c -Iinclude -Ltarget/release -lscap -lz -lelf
```
