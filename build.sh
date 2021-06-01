go build -buildmode=c-shared  -o libwormhole.so go_main.go
gcc mw.c -o mw -lwormhole -L.
