from Crypto.PublicKey import RSA
from os.path import exists
import os

def pki_connect(conn,addr):

	username = conn.recv(1024).decode()
	print(username)
	filename = username+".pem"
	if exists(filename):
		conn.send("False".encode())
	else:
		conn.send("True".encode())
	pub_key = RSA.importKey(conn.recv(10000), passphrase=None)
	if exists(filename):
		print("Public key already exists.")
		conn.send()
		return
	f = open(filename,'wb')
	f.write(pub_key.export_key('PEM'))
	f.close()
	conn.send("success".encode())
	conn.close()


def pki_query(conn,addr):

	username = conn.recv(1024).decode()
	filename = username+".pem"
	if not exists(filename):
		print("Public key not found.")
		return
	key = open(filename, 'rb').read()
	key = RSA.importKey(key, passphrase=None)
	conn.send(key.publickey().exportKey(format='PEM', passphrase=None, pkcs=1))
	conn.close()

def mail_reciever(conn,addr):
	
	sender = conn.recv(1024).decode()
	conn.send("True".encode())
	reciever = conn.recv(1024).decode()
	conn.send("True".encode())
	filename = reciever+"/"+sender+".txt"
	if not os.path.isdir(reciever):
		os.system("mkdir "+reciever)
	f = open(filename,'wb')
	f.write(conn.recv(100000))
	f.close()
	conn.close()
	

def mail_sender(conn,addr):
	
	sender = conn.recv(1024).decode()
	conn.send("True".encode())
	reciever = conn.recv(1024).decode()
	filename = reciever+"/"+sender+".txt"
	if not os.path.isdir(filename):
		conn.send("False".encode())
		return
	f = open(filename,'rb')
	conn.send(f.read())



