# -*- encoding: utf-8 -*-

import os
import select
import socket
import sys
import signal
import shlex
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
        if not self.is_locked():
            self.locked = (locker, True)
            return '%s has been acquired by %s.' % (self.name, locker)

        elif self.is_locked():
            # Already locked
            return '%s is already locked by %s.' % (self.name, self.locked[0])
        else:
            return 'Cannot lock %s. Object does not exist or contains an error.' % (self.name)

    def release(self, requester):
        # Locked, are you the person that locked it?
        if self.is_locked() and requester == self.locked[0]:
            # Unlock it
            self.locked = (None, False)
            return '%s has been released by %s.' % (self.name, requester)
        
        elif self.is_locked() and requester != self.locked[0]:
            # Locker and unlocker are not the same person
            return 'Cannot unlock %s. Already locked by %s.' % (self.name, self.locked[0])
            
        else:
            return 'Cannot unlock %s. This object is not locked or does not exist.' % (self.name)

    def note(self, content, requester):
        # If it's locked, are you the locker?
        if self.is_locked() and requester == self.locked[0]:
            # Add the note
            self.notes.append(content)
            return 'A note has been added to %s.' % (self.name)
        
        elif self.is_locked() and requester != self.locked[0]:
            return 'Cannot add note to %s. This object is locked by %s.' % (self.name, self.locked[0])

        elif not self.is_locked():
            # Add the note
            self.notes.append(content)
            return 'A note has been added to %s.' % (self.name)

        else:
            return 'Cannot add note to %s. This object does not exist.' % (self.name)
        
    def set_flag(self, content, requester):
        # If it's locked, are you the locker?
        if self.is_locked() and requester == self.locked[0]:
            # Add the flag
            self.flag = content
            return 'A flag has been added to %s.' % (self.name)
        
        elif self.is_locked() and requester != self.locked[0]:
            return 'Cannot add flag to %s. This object is locked by %s.' % (self.name, self.locked[0])

        elif not self.is_locked():
            # Add the flag
            self.flag = content
            return 'A flag has been added to %s.' % (self.name)

        else:
            return 'Cannot add flag to %s. This object does not exist.' % (self.name)
            

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
lock:    Lock object with name [name] (lock [name])
release: Release lock on object with name [name] (release [name])
note:    Add note "[note]" to object with name [name] (note [name] "[note]")
flag:    Add flag "[flag]" to object with name [name] (flag [name] "[flag]")
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
            try:
                cmd = shlex.split(data[1:])
            except ValueError, e:
                msg = 'Error: %s' % (str(e))
                self.send_encrypted(s, msg, self.get_just_name(s))
                return
            
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
list:     List all objects and their attributes
'''
                    # Send to self
                    self.send_encrypted(s, msg, self.get_just_name(s))
                    return
                    
            elif cmd[0].lower() == 'list':
                # Doesn't take any args
                if len(cmd) == 2:
                    msg = ''
                    for name,ob in self.objects.iteritems():
                        msg += '\nObject "%s":\n' % (name)
                        msg += 'Locked: %s\n' % (str(ob.locked))
                        msg += 'Notes: %s\n' % ('; '.join(ob.notes))
                        msg += 'Flag: %s\n' % (ob.flag)
                        
                    # Send to self
                    self.send_encrypted(s, msg, self.get_just_name(s))
                    return
                
                else:
                    msg = '''
Error: list does not accept any arguments
Usage:
list:     Add an object named [name] to the session (add [name])
'''
                    # Send to self
                    self.send_encrypted(s, msg, self.get_just_name(s))
                    return

            elif cmd[0].lower() == 'lock':
                # Takes one arg
                if len(cmd) == 3:
                    if cmd[1] in self.objects:
                        msg = self.objects[cmd[1]].acquire(self.get_just_name(s))
                        if 'is already locked' in msg:
                            # Send to self
                            self.send_encrypted(s, msg, self.get_just_name(s))
                            return
                        else:                         
                            # Send data to all
                            for o in self.outputs:
                                self.send_encrypted(o, msg, self.get_just_name(s))
                            return

                    else:
                        msg = '''
Error: object does not exist
Usage:
lock:     Lock object with name [name] (lock [name])
'''
                        # Send to self
                        self.send_encrypted(s, msg, self.get_just_name(s))
                        return
                        
                else:
                    msg = '''
Error: lock only accepts one argument
Usage:
lock:     Lock object with name [name] (lock [name])
'''                 # Send to self
                    self.send_encrypted(s, msg, self.get_just_name(s))
                    return   

            elif cmd[0].lower() == 'release':
                # Takes one arg
                if len(cmd) == 3:
                    if cmd[1] in self.objects:
                        msg = self.objects[cmd[1]].release(self.get_just_name(s))
                        if 'Cannot unlock' in msg:
                            # Send to self
                            self.send_encrypted(s, msg, self.get_just_name(s))
                            return
                        else:
                            # Send data to all
                            for o in self.outputs:
                                self.send_encrypted(o, msg, self.get_just_name(s))
                            return
                    else:
                        msg = '''
Error: object does not exist
Usage:
release:     Release object with name [name] (release [name])
'''
                        # Send to self
                        self.send_encrypted(s, msg, self.get_just_name(s))
                        return
                else:
                    msg = '''
Error: release only accepts one argument
Usage:
release:     Release object with name [name] (release [name])
'''                 # Send to self
                    self.send_encrypted(s, msg, self.get_just_name(s))
                    return
                
            elif cmd[0].lower() == 'note':
                # Takes two args
                if len(cmd) == 4:
                    if cmd[1] in self.objects:
                        msg = self.objects[cmd[1]].note(cmd[2], self.get_just_name(s))
                        # Send to self
                        self.send_encrypted(s, msg, self.get_just_name(s))
                        return
                    else:
                        msg = '''
Error: object does not exist
Usage:
note:     Add note "[note]" to object with name [name] (note [name] "[note]")
'''
                        # Send to self
                        self.send_encrypted(s, msg, self.get_just_name(s))
                        return
                else:
                    msg = '''
Error: note only accepts two arguments
Usage:
note:     Add note "[note]" to object with name [name] (note [name] "[note]")
'''
                    # Send to self
                    self.send_encrypted(s, msg, self.get_just_name(s))
                    return

            elif cmd[0].lower() == 'flag':
                # Takes two args
                if len(cmd) == 4:
                    if cmd[1] in self.objects:
                        msg = self.objects[cmd[1]].set_flag(cmd[2], self.get_just_name(s))
                        if 'has been added' in msg:
                            # Send data to all
                            for o in self.outputs:
                                self.send_encrypted(o, msg, self.get_just_name(s))
                            return
                        else:
                            # Send to self
                            self.send_encrypted(s, msg, self.get_just_name(s))
                            return
                
                    else:
                        msg = '''
Error: object does not exist
Usage:
flag:     Add flag "[flag]" to object with name [name] (flag [name] "[flag]")
'''
                        # Send to self
                        self.send_encrypted(s, msg, self.get_just_name(s))
                        return
                else:
                    msg = '''
Error: flag only accepts two arguments
Usage:
flag:     Add flag "[flag]" to object with name [name] (flag [name] "[flag]")
'''
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
                    for s, val in self.clientmap.iteritems():
                        if cname in [str(i) for i in val]: # Have to convert each one to prevent a __getstate__ error
                            continue # Want to abort the connection here!
                           
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
