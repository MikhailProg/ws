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


```
$ ./src/wscat

usage: [WS_SRV=] [WS_URI=/uri] wscat dest port

    WS_SRV and WS_URI are environment variables:
    * WS_SRV starts the program as a server.
    * WS_URI sets ws://dest:port/URI, default is '/cat'.

```

Run wscat as a server in one terminal:

```
$ WS_SRV= ./wscat localhost 1234
```

Run wscat as a client in another terminal:

```
$ ./wscat localhost 1234
```

A raw chat is opened (wscats standard [in|out]puts are connected with each other).

Run a remote shell:

```
$ mkfifo /tmp/io && bash -i 2>&1 </tmp/io | WS_SRV= ./wscat localhost 1234 >/tmp/io; rm -f /tmp/io
```

Connect to the remote shell:

```
$ ./wscat localhost 1234
```


To change WebSocket bind point set WS_URI variable.

The server provides a service at ws://localhost:1234/blah:

```
$ WS_SRV= WS_URI=/blah ./wscat localhost 1234
```

The client connects to ws://localhost:1234/blah:

```
$ WS_URI=/blah ./wscat localhost 1234
```

