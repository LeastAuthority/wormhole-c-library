This project builds a shared library and a header file from the
wormhole-william Go project. The resultant C header file and shared
library can be used in any C compatible runtime system that can call
into C via a foreign function interface (FFI). A demo C program that
uses the library to send a file and receive a text/file/directory is
provided.

The supplied Go code borrows code from [wormhole-william's
cmd](https://github.com/psanford/wormhole-william/tree/master/cmd)
package.

