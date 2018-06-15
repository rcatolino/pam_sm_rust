# PAM SM

Rust FFI wrapper to implement PAM service modules for Linux.

# Known issues :
Not all symbols are exported when linking the final module as a ``cdylib``. Linking as a ``dylib`` works fine.
