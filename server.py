#server program which will act as PKI and relay server
#This will act as a DNS as well as KDC for clients
import socket
import os
import hashlib
import threading
import sqlite3
import random
import string
from lib_funcs import *




def send_mail():
	sock = socket.socket()
	port = 6902
	sock.bind(('', port))
	print("Mail sender waiting for connections")
	while True:
		sock.listen(5)    
		conn, addr = sock.accept()
		threading.Thread(target=mail_sender, args=(conn,addr,)).start()


def recv_mail():
	sock = socket.socket()
	port = 6901
	sock.bind(('', port))
	print("Mail reciever waiting for connections")
	while True:
		sock.listen(5)  
		conn, addr = sock.accept()
		threading.Thread(target=mail_reciever, args=(conn,addr,)).start()

def pki_make_entry():
	sock = socket.socket()
	port = 6903
	sock.bind(('', port))
	print("Auth Listener waiting for connections")
	while True:
		sock.listen(5)    
		conn, addr = sock.accept()
		threading.Thread(target=pki_connect, args=(conn,addr,)).start()

def pki_listener():
	
	sock = socket.socket()
	port = 6904
	sock.bind(('', port))
	print("Auth Listener waiting for connections")
	while True:
		sock.listen(5)    
		conn, addr = sock.accept()
		threading.Thread(target=pki_query, args=(conn,addr,)).start()

def main():

	threading.Thread(target=send_mail, args=()).start()
	threading.Thread(target=recv_mail, args=()).start()
	threading.Thread(target=pki_make_entry, args=()).start()
	threading.Thread(target=pki_listener, args=()).start()


if __name__ == "__main__":
	main()

