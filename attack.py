#!/usr/bin/sage

from sage.all import *
import struct
import re
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random

# Our "MPI" format consists of 4-byte integer length l followed by l bytes of binary key
def int_to_mpi(z):
    s = int_to_binary(z)
    return struct.pack('I',len(s))+s

# Horrible hack to get binary representation of arbitrary-length long int
def int_to_binary(z):
    s = ("%x"%z); s = (('0'*(len(s)%2))+s).decode('hex')
    return s

encrypt_header = '-----BEGIN PRETTY BAD ENCRYPTED MESSAGE-----\n'
encrypt_footer = '-----END PRETTY BAD ENCRYPTED MESSAGE-----\n'

# PKCS 7 pad message.
def pad(s,blocksize=AES.block_size):
    n = blocksize-(len(s)%blocksize)
    return s+chr(n)*n

def parse_mpi(s,index):
    length = struct.unpack('<I',s[index:index+4 ])[0]
    z = Integer(s[index+4 :index+4 +length].encode('hex'),16 )
    return z, index+4 +length

# Encrypt string s using RSA encryption with AES in CBC mode.
# Generate a 256-bit symmetric key, encrypt it using RSA with PKCS1v1.5 type 1 padding, and prepend the MPI-encoded RSA ciphertext to the AES-encrypted ciphertext of the message.
def encrypt(rsakey,s):
    m = ZZ.random_element(2**256)

    k = ceil(rsakey.size()/8)-3-32
    EB = '0001' + 'ff'*k + '00' + "%x"%m
    print len(hex(m))
    
    output = int_to_mpi(rsakey.encrypt(int(EB,16),None))

    aeskey = int_to_binary(m)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(aeskey, AES.MODE_CBC, iv)

    output += iv + cipher.encrypt(pad(s))

    return encrypt_header + output.encode('base64') + encrypt_footer

def get_decryption(cipher, pubkey):

	R = PolynomialRing(ZZ,'x')
	x = R.gen()

	# Store the modulo N
	N = pubkey.n

	# Get value of k
	k = ceil(pubkey.size()/8) - 3 - 32

	# Generate prefix and postfix
	pre = '0001' + 'ff'*k + '00' + '0'*64
	a = Integer(int(pre,16), base = 35)

	post = 'x'*64
	X = Integer(post, base = 35)

	# Parse the ciphertext to get rid of the header and footer
	ct = re.search(encrypt_header+"(.*)"+encrypt_footer,cipher,flags=re.DOTALL).group(1).decode('base64')
	index = 0 

	# Get encrypted aes secret key and iv
	aes_key_enc, index = parse_mpi(ct,index)
	aes_key_enc = Integer(mod(aes_key_enc,N), base = 35)
	iv = ct[index:index + 16]
	enc_msg = ct[index + 16 : ]

	#Construct the matrix
	M = matrix(ZZ, [[X**3, 3*(X**2)*a, 3*X*(a**2), (a**3)-aes_key_enc], [0,N*(X**2),0,0],[0,0,N*X,0],[0,0,0,N]])

	#Get the reduced basis
	B = M.LLL()

	#Construct the polynomial
	Q = B[0][0]*(x**3)/(X**3)+B[0][1]*(x**2)/(X**2)+B[0][2]*x/X + B[0][3]
	root = Q.roots(ring = ZZ)[0][0].str(base = 16)
	root = int_to_binary(int(root, 16))

	cipher = AES.new(root, AES.MODE_CBC, iv)
	output = cipher.decrypt(pad(enc_msg))
	return output


if __name__=='__main__':
    pubkey = RSA.importKey(open('key.pub').read())
    cipher = open('hw6.pdf.enc.asc').read()
    out = get_decryption(cipher, pubkey)
    f = open('HW_DECRYPTED', 'w')
    f.write(out)
    f.close()


