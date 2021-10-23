#client program
import socket
import sys
import hashlib
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad,unpad
from os.path import exists


HOST = "10.138.0.3"
SEND_PORT = 6901
RECV_PORT = 6902
PKI_ENTRY_PORT = 6903
PKI_QUERY_PORT = 6904

global public_nonce


def get_key(username):
	conn = socket.socket()
	conn.connect((HOST,PKI_QUERY_PORT)) 
	conn.send(username.encode())
	try:
		pub_key = RSA.importKey(conn.recv(10000), passphrase=None)
	except:
		print("User does not exist.")
		sys.exit()
	conn.close()
	f = open(username+".pem",'wb')
	f.write(pub_key.export_key('PEM'))
	f.close()


def make_priv_pub_key(username):

	key = RSA.generate(2048)
	f = open('private_key.pem','wb')
	f.write(key.export_key('PEM'))
	f.close()
	conn = socket.socket()
	conn.connect((HOST,PKI_ENTRY_PORT))
	conn.send(username.encode())
	if conn.recv(1024).decode() == "False":
		return
	conn.send(key.publickey().exportKey(format='PEM', passphrase=None, pkcs=1))
	status = conn.recv(1024).decode()
	if(status == "success"):
		print("Key entry successfully created.")
	elif(status == "fail"):
		print("Key already exists.")

#function to generate RSA public and private key

def send_mail():

	sender = input("Enter your (sender) username: ")
	reciever = input("Enter reciever's username: ")
	inputMessage = input('Enter message for mail: ')

	#Create the hash of the inputMessage
	inputMessageHashed = SHA256.new(inputMessage.encode())
	
	if not exists("private_key.pem"):
		make_priv_pub_key(sender)

	#Signing the hashed input message using Alices's key.
	signer = PKCS1_v1_5.new(RSA.import_key(open('private_key.pem').read()))
	sender_signature = signer.sign(inputMessageHashed)

	#Concatenate the inputMessage and sender_signature
	messageAndSign = inputMessage.encode() + b'\n\n\n\n\n' + sender_signature
	
	#One time secret key
	key = get_random_bytes(16)
	
	# AES Encryption using one time secret key
	aes = AES.new(key, AES.MODE_CBC)
	encryptedMessage = aes.encrypt(pad(messageAndSign, AES.block_size))


	get_key(reciever)
	pub_key_file = reciever + '.pem'
	#Encrypting the one time secret key using Bob's public key
	rsa = PKCS1_OAEP.new(RSA.import_key(open(pub_key_file).read()))
	encryptedkey = rsa.encrypt(key)
	#Concatenate the encrypted key with encrypted inputMessage
	finalMessage = encryptedkey + b'\n\n\n\n\n' + aes.iv + b'\n\n\n\n\n' + encryptedMessage

	sock = socket.socket()
	sock.connect((HOST,SEND_PORT))
	sock.send(sender.encode())
	sock.recv(1024)
	sock.send(reciever.encode())
	sock.recv(1024)
	sock.send(finalMessage)
	sock.close()

def recv_mail():

	conn = socket.socket()
	conn.connect((HOST,RECV_PORT))
	reciever = input("Enter your (reciever) username: ")
	sender = input("Enter sender's username: ")
	conn.send(sender.encode())
	conn.recv(1024)
	conn.send(reciever.encode())
	if conn.recv(1024).decode() == "False":
		print("No mails!")
		conn.close()
		return
	#gets public key of sender
	get_key(sender)
	pub_key_file = sender + '.pem'

	encryptedMessage = conn.recv(100000000)
	#Separating the different parts of the message
	splitMessage = encryptedMessage.split(b'\n\n\n\n\n')
	#Decrypt the one time secret key
	rsa = PKCS1_OAEP.new(RSA.import_key(open('private_key.pem').read()))
	key = rsa.decrypt(splitMessage[0])
	#Now decrypting the message
	aes = AES.new(key,AES.MODE_CBC,splitMessage[1])
	messageSignature = aes.decrypt(splitMessage[2])
	messageAndSignature = unpad(messageSignature, AES.block_size)
	originalEmail = messageAndSignature.split(b'\n\n\n\n\n')
	textEmail = originalEmail[0]
	#Creating the hash of the message to be verified.
	textEmailHashed = SHA256.new(textEmail)
	#Verifying the signature of the sender.
	keyVerifier = PKCS1_v1_5.new(RSA.import_key(open(pub_key_file).read()))
	if (keyVerifier.verify(textEmailHashed, originalEmail[1])):
		print("\nKey Verified")
		print("Recieved Email: ", textEmail.decode())
	else:
		print("Signature verification unsuccessful")



def main():

	ch = input("\n1.Register with PKI\n2.Send email\n3.Recieve email\n\nChoice: ")
	if ch ==  '1':
		username = input("Enter username: ")
		make_priv_pub_key(username)
	elif ch == '2':
		send_mail()
	elif ch == '3':
		recv_mail()
	else:
		print("Invalid choice")
		

if __name__ == "__main__":
	main()
