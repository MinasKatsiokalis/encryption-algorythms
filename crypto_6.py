"""
----------------------------------  
Minas Katsiokalis
AM: 2011030054 
email: minaskatsiokalis@gmail.com           
----------------------------------
"""
import crypto_1
import crypto_4

"""
-----------------------------------------
	Generation of AES key using SHA-256
-----------------------------------------
"""

#generates a key for AES-128 based on the hashed password of user
def generateHashedUserKey(password):
	aes = crypto_1.AES()
	sha256 = crypto_4.SHA()

	#hashing the password with SHA 256
	str1 = ''.join(str(e) for e in password)
	sha_pass = sha256.sha256_lib(str1)

	#generate a key with the hash of password
	aes_pass = aes.generateUserKey(sha_pass[:16])
	return aes_pass