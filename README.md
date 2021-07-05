# KIT
Keep In Touch - C single header library for IPC

# Features
 - Single header library
 - Fast
 - Built-in custom protocol
 - ECDH key exchange for handshake
 - AES-128 encrypted communication
 - Cryptographically secure random number generation for IV and other stuff
 - Easy to use API
 - Small footprint
 - Process safe & Thread safe

# Protocol format ( *kpacket* )

This is how a single packet looks like

```
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Flags |  Type | Crc32 |RID|    Data ptr   |R|     Length    | |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Type |                                                         |
+-+-+-+                                                         +
|                                                               |
+                                                               +
|                              Data                             |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
The packets is composed by an header and a body.

Inside the header we can find:
 - Packet Flags [\*](#header---packet-type-and-flags)
 - Packet Type [\*](#header---packet-type-and-flags)
 - Checksum (crc32)
 - PID (Packet ID)
 - Data pointer (pointer to the body)
 - Readed (flag which indicate if the packet was readed)

On the other side we have the following fields inside the body:
 - Data Length (length of the actual data)
 - Data Type (can be any of ***KIT_DATA_TEXT*** and ***KIT_DATA_BINARY***)
 - Data (the actual data)

# Header - Packet Type and Flags

Packet Type and Flags have multiple usage mainly they are used during hadshake to keep track of the various stages, but can be used also to notify the endpoint abount:
 - Binding (***KIT_TYPE_BIND*** and ***KIT_FLAG_BINDED***)
 - Connection (***KIT_TYPE_CONNECT*** and ***KIT_FLAG_CONNECTED***)
 - Disconnection (***KIT_TYPE_DISCONNECT*** and ***KIT_FLAG_DISCONNECTED***)
 - Client Accept (***KIT_TYPE_ACCEPT*** and ***KIT_FLAG_ACCEPTED***)
 - Handshake stage (***KIT_TYPE_HANDSHAKE*** and ***KIT_FLAG_CLIENT_HANDSHAKE*** or ***KIT_FLAG_SERVER_HANDSHAKE***)

# Body

The body of the packet is self-describing and don't need futher explaination.

# API
There are 2 kinds of API in KIT safe api and unsafe ones, safe api can be used everytime in your program , while unsafe ones should never be called from an external program, they are only called internally by KIT. They still can be used and provide low level access to the underlying datastructure and protocol.

## Safe API

Below the list of safe api:

```c
SAFEAPI kbool kit_init();
SAFEAPI kbool kit_bind(IN kcstring id, OUT pkinstance instance);
SAFEAPI kit_action kit_select(IN pkinstance instance);
SAFEAPI kbool kit_disconnect(IN pkinstance instance);
SAFEAPI pkpacket kit_read(IN pkinstance instance);
SAFEAPI kbool kit_write(IN pkinstance instance, IN kbinary* data, ksize length);
SAFEAPI kbool kit_connect(IN kcstring id, OUT pkinstance instance);
SAFEAPI kbool kit_listen_and_accept(IN pkinstance instance);
SAFEAPI kuint32 kit_get_error();
SAFEAPI kcstring kit_human_error();
```

## Unsafe API

Below the list of unsafe api

```c
UNSAFEAPI kvoid kit_set_read(IN pkinstance instance);
UNSAFEAPI kvoid kit_decrypt_packet(IN pkinstance instance, IN pkpacket pkt);
UNSAFEAPI kvoid kit_encrypt_packet(IN pkinstance instance, IN pkpacket pkt);
UNSAFEAPI kbool kit_client_handshake(IN pkinstance instance);
UNSAFEAPI kbool kit_read_packet(IN pkinstance instance, OUT pkpacket pkt);
UNSAFEAPI kbool kit_write_packet(IN pkinstance instance, IN pkpacket packet);
UNSAFEAPI kbool kit_make_packet(IN kit_packet_type ptype, IN kit_data_type dtype, IN kit_packet_flags flags, IN ksize datasize, IN kptr data, OUT pkpacket packet);
UNSAFEAPI kvoid kit_set_error(IN kit_error errid);
UNSAFEAPI kuint32 kit_crc32(IN kptr data, IN ksize datasize);
UNSAFEAPI kbool kit_fill_secure_random(IN kptr buffer, IN ksize size);
```

# Server example

Starting a KIT server is easy as:

```c
#include <kit.h>
#include <stdio.h>

int main() {
  // First initialize KIT
  if (kit_init()) {
    // Declare a KIT instance this struct hold all the needed information for KIT to works
    kinstance instance = {0};
    if(kit_bind(KIT_DEFAULT_ID, &instance)) {
      if(kit_listen_and_accept(&instance)) {
        // Got a connection
        // Now you can use kit_select or kit_read / kit_write
      }else{
        printf("kit_listen_and_accept error: %s\n", kit_human_error());
      }
    }else{
      printf("kit_bind error: %s\n", kit_human_error());
    }
  }
}
```

# Client example

Connecting to a KIT server is easy as:

```c
#include <kit.h>
#include <stdio.h>

int main() {
  // First initialize KIT
  if (kit_init()) {
    // Declare a KIT instance this struct hold all the needed information for KIT to works
    kinstance instance = {0};
    // Use the same ID used on server side
    if(kit_connect(KIT_DEFAULT_ID, &instance)) {
      // Now you can use kit_select or kit_read / kit_write
      if(kit_disconnect(&instance)) {
        printf("Client disconnected!\n");
        return 0;
      }else{
        printf("kit_disconnect error: %s\n", kit_human_error());
      }
    }else{
      printf("kit_connect error: %s\n", kit_human_error());
    }
  }
}
```

# Windows select-like interface for KIT

KIT have also a select-like API which could facilitate message exchange between client and server that's how could be used:

```c
#include <kit.h>

int server_handle_client(pkinstance instance) {
  while(KTRUE) {
    switch(kit_select(instance)) {
      case KIT_CAN_READ:
        // perform a kit_read
        break;
      case KIT_CAN_WRITE:
        // perform a kit_write
        break;
    }
  }
}
```

# License

Check the first lines of the kit.h header file :D
