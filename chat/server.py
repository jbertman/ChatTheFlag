# -*- encoding: utf-8 -*-

import os
import select
import socket
import sys
import signal
from time import sleep

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA

from communication import send, receive


class CTFObject(object):
    def __init__(self, name):
        self.name = name
        self.locked = (None, False)
        self.notes = []
        self.flag = ''
        
    def is_locked(self):
        return self.locked[1]

    def acquire(self, locker):
        # Not locked yet, acquire it
        if not is_locked(self):
            self.locked[0] = locker
            self.locked[1] = True
            return '%s has been acquired by %s.' % (self.name, locker)

        elif is_locked(self):
            # Already locked
            return '%s is already locked by %s.' % (self.name, self.locked[0])
        else:
            return 'Cannot lock %s. Object does not exist or contains an error.' % (self.name)

    def release(self, requester):
        # Locked, are you the person that locked it?
        if is_locked(self) and requester == self.locked[0]:
            # Unlock it
            self.locked[0] = None
            self.locked[1] = False
            return '%s has been released by %s.' % (self.name, requester)
        
        elif is_locked(self) and requester != self.locked[0]:
            # Locker and unlocker are not the same person
            return 'Cannot unlock %s. Already locked by %s.' % (self.name, self.locked[0])
            
        else:
            return 'Cannot unlock %s. This object is not locked or does not exist.' % (self.name)
            

class ChatServer(object):

    def __init__(self, address='127.0.0.1', port=3490):
        self.clients = 0

        self.objects = {}

        # Client map
        self.clientmap = {}

        # Output socket list
        self.outputs = []

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((address, int(port)))

        print 'Generating RSA keys ...'
        self.server_privkey = RSA.generate(4096, os.urandom)
        self.server_pubkey = self.server_privkey.publickey()

        print 'Listening to port', port, '...'
        self.server.listen(5)

        # Trap keyboard interrupts
        signal.signal(signal.SIGINT, self.sighandler)

    def sighandler(self, signum, frame):
        # Close the server
        print 'Shutting down server...'

        # Close existing client sockets
        for o in self.outputs:
            o.close()

        self.server.close()

    def getname(self, client):
        # Return the printable name of the
        # client, given its socket...
        info = self.clientmap[client]
        host, name = info[0][0], info[1]
        return '@'.join((name, host))

    def get_just_name(self, client):
        return self.clientmap[client][1]

    def send_encrypted(self, to_who, message, name):
        try:
            encryptor = self.clientmap[to_who][2]
            msg = encryptor.encrypt(message, 0)
            send(to_who, msg)

        except IOError:
            send(to_who, 'PLAIN: cannot find public key for: %s' % name)

    def verify_signature(self, client, message, signature):
        try:
            key = self.clientmap[client][2]
            msg_hash = SHA.new()
            msg_hash.update(message)

            verifier = PKCS1_PSS.new(key)
            return verifier.verify(msg_hash, signature)

        except IOError:
            return False

    def print_help(self, s):
        msg ='''
Available commands:

help:    Show this help message
add:     Add an object named [name] to the session (add [name])
list:    List all objects and their attributes

'''
        # Send help only to self
        self.send_encrypted(s, msg, self.get_just_name(s))

    def process(self, data, s):
        if data[0] != '!': # No server-side commands
            # Send as new client's message...
            msg = '\n# [' + self.getname(s) + ']>> ' + data

            # Send data to all except ourselves
            for o in self.outputs:
                if o != s:
                    self.send_encrypted(o, msg, self.get_just_name(s))
            return
        
        else:
            # Server-side command
            cmd = data[1:].split(' ')
            if cmd[0].lower() == 'help':
                self.print_help(s)
                return

            elif cmd[0].lower() == 'add':
                if len(cmd) == 3: # Include verification
                    if cmd[1] not in self.objects:
                        # Add the object
                        self.objects[cmd[1]] = CTFObject(cmd[1])
                        return
                        
                    else:
                        msg = '\nObject already exists. Try listing the current objects instead.'
                        self.send_encrypted(s, msg, self.get_just_name(s))
                        return
                else:
                    msg = '''
Error: add only accepts 1 argument
Usage:
add:     Add an object named [name] to the session (add [name])
'''
                    # Send to self
                    self.send_encrypted(s, msg, self.get_just_name(s))
                    return
                    
            elif cmd[0].lower() == 'list':
                if len(cmd) == 2:
                    msg = ''
                    for name,ob in self.objects.iteritems():
                        msg += '\n%s:\n' % (name)
                        msg += 'Locked: %s\n' % (str(ob.locked))
                        msg += 'Notes: %s\n' % (ob.notes)
                        msg += 'Flag: %s' % (ob.flag)
                        
                    # Send to self
                    self.send_encrypted(s, msg, self.get_just_name(s))
                    return    
            else:
                # Unrecognized command
                self.print_help(s)
                return
            

    def serve(self):
        inputs = [self.server, sys.stdin]
        self.outputs = []

        running = 1

        while running:
            try:
                inputready, outputready, exceptready = select.select(inputs, self.outputs, [])

            except select.error:
                break

            except socket.error:
                break

            for s in inputready:
                if s == self.server:
                    # handle the server socket
                    client, address = self.server.accept()
                    print 'chatserver: got connection %d from %s' % (client.fileno(), address)
                    # Get client public key and send our public key
                    pubkey = RSA.importKey(receive(client))
                    send(client, self.server_pubkey.exportKey())

                    # Read the login name
                    cname = receive(client).split('NAME: ')[1]

                    # Compute client name and send back
                    self.clients += 1
                    send(client, 'CLIENT: ' + str(address[0]))
                    inputs.append(client)

                    self.clientmap[client] = (address, cname, pubkey)

                    # Send joining information to other clients
                    msg = '\n(Connected: New client (%d) from %s)' % (self.clients, self.getname(client))

                    for o in self.outputs:
                        try:
                            self.send_encrypted(o, msg, self.get_just_name(o))

                        except socket.error:
                            self.outputs.remove(o)
                            inputs.remove(o)

                    self.outputs.append(client)

                elif s == sys.stdin:
                    # handle standard input
                    sys.stdin.readline()
                    running = 0
                else:

                    # handle all other sockets
                    try:
                        data = receive(s)

                        if data:
                            dataparts = data.split('#^[[')
                            signature = dataparts[1]
                            data = dataparts[0]

                            verified = self.verify_signature(s, data, signature)
                            data = self.server_privkey.decrypt(data) # Server can decide parsing here

                            if data != '\x00':
                                if verified:
                                    data = '%s [OK]' % data
				    
                                else:
                                    data = '%s [Not verified]' % data
				
				self.process(data, s) # parse out server-side commands or send as-is

                        else:

                            print 'Chatserver: Client %d hung up' % s.fileno()
                            self.clients -= 1
                            s.close()
                            inputs.remove(s)
                            self.outputs.remove(s)

                            # Send client leaving information to others
                            msg = '\n(Hung up: Client from %s)' % self.getname(s)

                            for o in self.outputs:
                                self.send_encrypted(o, msg, self.get_just_name(o))

                    except socket.error:
                        # Remove
                        inputs.remove(s)
                        self.outputs.remove(s)

            sleep(0.1) # Don't kill the main thread!

        self.server.close()

if __name__ == "__main__":

    if len(sys.argv) < 3:
        sys.exit('Usage: %s listen_ip listen_port' % sys.argv[0])

    ChatServer(sys.argv[1], sys.argv[2]).serve()
