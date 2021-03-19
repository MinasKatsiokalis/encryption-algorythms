"""
----------------------------------  
Minas Katsiokalis
AM: 2011030054 
email: minaskatsiokalis@gmail.com           
----------------------------------
"""
import crypto_3
import crypto_4

rsa = crypto_3.RSA()
sha256 = crypto_4.SHA()

"""
-----------------------------------------
	Signature Creation and Validation
-----------------------------------------
"""

#Creates a signature using the data, and private key (n,d)
def signature(data, n, d):
	#we are hashing the data with SHA 256
	str1 = ''.join(str(e) for e in data)
	sha_data = sha256.sha256_lib(str1)

	#create the signature using private key 
	sign = rsa.decrypt(sha_data, n, d)
	return sign 

#Validation of signature using public key (n,e)
def validation(signature, data, n, e):
	#we are hashing the data with SHA 256
	str1 = ''.join(str(e) for e in data)
	sha_data = sha256.sha256_lib(str1)

	#check if signature is the same with hashed data
	sign = rsa.decrypt(signature, n, e)
	if sign == sha_data:
		return True
	else:
		return False