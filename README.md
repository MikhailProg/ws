# WebSocket

A small stream WebSocket library. It includes wscat program (nc like) which demonstrates all API usage.

## Build

```
$ make -C src
```

Build with fuzz IO

```
$ make -C src IOFUZZ=1
```

## Usage and run

wscat links the local standard [in|out]puts with the remote side via a network socket. The program works as a WebSocket client or as a WebSocket server.

There is also a web wscat which works as a client (lives in static folder).

```
$ ./src/wscat

usage: [WS_SRV=] [WS_URI=/uri] wscat dest port

    WS_SRV and WS_URI are environment variables:
    * WS_SRV starts the program as a server.
    * WS_URI sets ws://dest:port/URI, default is '/cat'.
```

Run a raw chat (wscats standard [in|out]puts are connected with each other):

```
$ WS_SRV= ./wscat localhost 1234
```

Run the client in another terminal:

```
$ ./wscat localhost 1234
```

Run the server as an echo server:

```
$ mkfifo /tmp/io && cat </tmp/io | WS_SRV= ./wscat localhost 1234 >/tmp/io; rm -f /tmp/io
```

Or run the server as a remote shell:

```
$ mkfifo /tmp/io && bash -i 2>&1 </tmp/io | WS_SRV= ./wscat localhost 1234 >/tmp/io; rm -f /tmp/io
```

Connect to the echo or remote shell from the other terminal:

```
$ ./wscat localhost 1234
```

Or open file:///path/to/ws/static/index.html in a browser and use an input field as if it is a standard input.

