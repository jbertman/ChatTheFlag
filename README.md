Encrypted Python chatroom for use in team-based CTFs using object-oriented paradigms
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

