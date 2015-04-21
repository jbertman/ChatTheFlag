ChatTheFlag
=====================================================

About
-----

This is a CTF chatserver that uses server-client RSA key-based authentication. Keypairs are generated dynamically, so there is no need to create encrypted keys for the client or server.

The idea behind this server is to centralize storage to increase collaboration. Clients can store hashes, see what challenges others are working on, add notes to specific objects, etc. I'll continue adding features, but feel free to submit a pull request if you have a cool idea. 

Installation:
-------------
    git clone https://github.com/jbertman/ChatTheFlag.git
    pip install -r REQUIREMENTS.txt

For server:
-----------
    python server.py listen_ip listen_port

For clients:
------------
    python client.py username server_ip server_port
    
Usage:
------
Clients can use the "!" symbol to run server-side commands. Run !help to see available commands:
```
[jbertman@127.0.0.1]> !help
Available commands:

help:    Show this help message
add:     Add an object named [name] to the session (add [name])
list:    List all objects and their attributes
lock:    Lock object with name [name] (lock [name])
release: Release lock on object with name [name] (release [name])
note:    Add note "[note]" to object with name [name] (note [name] "[note]")
flag:    Add flag "[flag]" to object with name [name] (flag [name] "[flag]")
```
An example of adding challenges, locking them, and adding a flag
```
[jbertman@127.0.0.1]> !add challenge_1
[jbertman@127.0.0.1]> !lock challenge_1
challenge_1 has been acquired by jbertman.
[jbertman@127.0.0.1]> !flag challenge_1 "{A_FLAG}"
A flag has been added to challenge_1.
[jbertman@127.0.0.1]> !list
Object "challenge_1":
Locked: ('jbertman', True)
Notes: 
Flag: {A_FLAG}
```
Another user connecting and trying operations on the previously locked objects
```
python client.py user2 127.0.0.1 8000
Connected to chat server 127.0.0.1:8000
[user2@127.0.0.1]> !add challenge_1
Object already exists. Try listing the current objects instead.
[user2@127.0.0.1]> !note challenge_1 "A note!"
[user2@127.0.0.1]> Cannot add note to challenge_1. This object is locked by jbertman.
```
TODO: Prevent duplicate users (https://github.com/jbertman/ChatTheFlag/issues/1), add password protection, note removal, and unlock requests
