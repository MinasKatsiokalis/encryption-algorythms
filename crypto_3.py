"""
----------------------------------  
Minas Katsiokalis
AM: 2011030054 
email: minaskatsiokalis@gmail.com           
----------------------------------
"""
"""
-----------------------------------------
 Encryptions/Decryption Functions of RSA
-----------------------------------------
"""
class RSA(object):
    #encryption using public key
    def encrypt(self, plaintext, n, e):
        output = []
        for i in range(0,len(plaintext)):
            output.append(pow(plaintext[i], e, n))
        return output

    #decryption using private key 
    def decrypt(self, ciphertext, n, d):
        output = []
        for i in range(0,len(ciphertext)):
            output.append(pow(ciphertext[i], d, n))
        return output

