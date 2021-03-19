"""
----------------------------------  
Minas Katsiokalis
AM: 2011030054 
email: minaskatsiokalis@gmail.com           
----------------------------------
"""
import pickle
import crypto_1
import random
from collections import namedtuple

"""
-----------------------------------------
            Helpfull function
-----------------------------------------
"""

#Check if 2 numbers are coprime
def coprime(a, b):
    #Two numbers are coprime if there is no integer (except 1) that divides both.
    for n in range(2, min(a, b) + 1):
        if a % n == b % n == 0:
            return False
    return True

"""
-----------------------------------------
            Keys Generation
-----------------------------------------
"""

#Generates the valus n,e,d for public,private keys of RSA
def generateRSAkeys(length):
    #cannot run for lenght <4
    if length < 4:
        print("\nLength must be >= 4!")
        return None,None,None

    #with the given length we can have a number in range (n_min,n_max)
    min_n = 1 << (length - 1)
    max_n = (1 << length) - 1

    #the upper and lower bound for prime number search
    upper = 1 << (length // 2 + 1)
    lower = 1 << (length // 2 - 1)
    

    primes = [2]

    #Find all primes in range(3,upper)
    for num in range(3, upper + 1, 2):
        for p in primes:
            if num % p == 0:
                break
        else:
            primes.append(num)

    while primes and primes[0] < lower:
        del primes[0]


    #Find p,q primes that are in the range for our length
    while primes:
        p = random.choice(primes)
        primes.remove(p)
        q_candidates = []
        for q in primes:
            if min_n <= p * q <= max_n:
                q_candidates.append(q)
        if q_candidates:
            q = random.choice(q_candidates)
            break
    else:
        print("\nNo p,q can be found!")
        return None,None,None
        

    #Choose an integer e such that 1 < e < phi(n) and e and phi(n) are coprime.
    n = p * q 
    phi_n = (p - 1) * (q - 1)
    for e in range(3, phi_n):
        if coprime(e, phi_n):
            break
    else:
        print("\nNo e can be found!")
        return None,None

    #Find d that (d * e - 1) is divisible by phi(n)
    for d in range(3, phi_n,2):
        if d * e % phi_n == 1:
            break
    else:
        print("\nNo d can be found!")
        return None,None,None

    #Return public(n,e) and private(n,d) keys.
    return n,e,d


"""
-----------------------------------------
            Save Keys to Disk
-----------------------------------------
"""
#Save both keys on disk, private is encrypted with the given key
def savePair(n, e, d, encryptionKey):
    publicKey = [n,e]
    privateKey = [n,d]

    #encrypt the ptivate key before save it on file
    aes_128 = crypto_1.AES()
    privateKey = aes_128.AES_ECBmodeEncryption(privateKey,encryptionKey)

    key_file = open("keys.pair", "w")
    pickle.dump(publicKey, key_file)
    pickle.dump(privateKey, key_file)
    key_file.close()

#Retrieves both keys, private is decrypted with the given key
def retrievePair(encryptionKey):
    key_file = open("keys.pair", "r")
    publicKey =  pickle.load(key_file)
    privateKey = pickle.load(key_file)

    #decrypt the private key before return it
    aes_128 = crypto_1.AES()
    privateKey = aes_128.AES_ECBmodeDecryption(privateKey,encryptionKey)
    privateKey = [privateKey[0],privateKey[1]]

    key_file.close()
    return publicKey,privateKey

#Save public key
def savePublic(n,e):
    publicKey = [n,e]

    key_file = open("key.pub", "w")
    pickle.dump(publicKey, key_file)
    key_file.close()

#Retrieve public key
def retrievePublic():
    key_file = open("key.pub", "r")
    publicKey =  pickle.load(key_file)
    key_file.close()
    return publicKey

#Save private key and encrypt it
def savePrivate(n,d,encryptionKey):
    privateKey = [n,d]

    key_file = open("key.sec", "w")

    aes_128 = crypto_1.AES()
    privateKey = aes_128.AES_ECBmodeEncryption(privateKey,encryptionKey)

    pickle.dump(privateKey, key_file)
    key_file.close()

#Retrive private key and decrypt it
def retrievePrivate(encryptionKey):
    key_file = open("key.sec", "r")
    privateKey =  pickle.load(key_file)

    aes_128 = crypto_1.AES()
    privateKey = aes_128.AES_ECBmodeDecryption(privateKey,encryptionKey)
    privateKey = [privateKey[0],privateKey[1]]

    key_file.close()
    return privateKey

