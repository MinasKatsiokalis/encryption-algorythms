"""
----------------------------------  
Minas Katsiokalis
AM: 2011030054 
email: minaskatsiokalis@gmail.com           
----------------------------------
"""

import crypto_1 as c1
import crypto_2 as c2
import crypto_3 as c3
import crypto_4 as c4
import crypto_5 as c5
import crypto_6 as c6


       
if __name__ == "__main__":
    
    #key for AES
    key  = [0x2b, 0x7e ,0x15 ,0x16 ,0x28 ,0xae ,0xd2 ,0xa6 ,0xab ,0xf7 ,0x15 ,0x88 ,0x09 ,0xcf ,0x4f ,0x3c]
    #plain text for AES
    text = [0x6b, 0xc1 ,0xbe ,0xe2 ,0x2e ,0x40 ,0x9f ,0x96 ,0xe9 ,0x3d ,0x7e ,0x11 ,0x73 ,0x93 ,0x17 ,0x2a]
    #init vectoer for AESCBC mode
    IV   = [0xb2, 0xe3, 0x83, 0x31, 0xaf, 0xef, 0xf0, 0x76, 0xcc, 0xe7, 0xa5, 0xc3, 0x0b, 0xa3, 0x0e ,0x08]
    #password of user
    pw   = [0xb2, 0xe3, 0x83, 0x31, 0xaf, 0xef, 0xf0, 0x76, 0xcc, 0xe7, 0xa5, 0xc3, 0x0b]
    
    """
    -----------------------------------------
    
     reprsesentation of crypto_1 methods
     
    -----------------------------------------
    """
    print"\n-----------------------------------------"
    print"reprsesentation of crypto_1 methods"
    print"-----------------------------------------"
    
    cipher = c1.AES()
    
    cipher.saveKey(key)
    print "\nKey saved successfully!"
    
    out = cipher.retrieveKey()
    print "\nRetrieving key..."
    print '[{}]'.format(', '.join(hex(x) for x in out))
    
    out = cipher.generateUserKey(pw)
    print "\nPassword: ",'[{}]'.format(', '.join(hex(x) for x in pw))
    print "\nGenerated Key: "
    print '[{}]'.format(', '.join(hex(x) for x in out))
    
    out = cipher.AES_ECBmodeEncryption(text,key)
    if out == None:
        print "\nNot valid size of key (16-byte required!)"
    else:
        print "\n(ECB)The cipher text is:"
        print '[{}]'.format(', '.join(hex(x) for x in out))
        
    out= cipher.AES_ECBmodeDecryption(out,key)
    if out == None:
        print "\nNot valid size of key (16-byte required!)"
    else:    
        print "\n(ECB)The plain text is:"
        print '[{}]'.format(', '.join(hex(x) for x in out)) 
        
    out = cipher.AES_CBCmodeEncryption(text,key,IV)
    if out == None:
        print "\nNot valid size of key (16-byte required!)"
    else:
        print "\n(CBC)The cipher text is:"
        print '[{}]'.format(', '.join(hex(x) for x in out))
        
    out= cipher.AES_CBCmodeDecryption(out,key,IV)
    if out == None:
        print "\nNot valid size of key (16-byte required!)"
    else:    
        print "\n(CBC)The plain text is:"
        print '[{}]'.format(', '.join(hex(x) for x in out))
        

    """
    -----------------------------------------
    
     reprsesentation of crypto_2 methods
     
    -----------------------------------------
    """
    
    print"\n-----------------------------------------"
    print"reprsesentation of crypto_2 methods"
    print"-----------------------------------------"
    
    length = 8
    #generate RSA public/private key
    N,E,D = c2.generateRSAkeys(length)
    print "\nGenerated RSA keys of modulus lenght:",length
    print "n:",hex(N),"e:",hex(E),"d:",hex(D)

    c2.savePair(N,E,D,key)
    print "\nPair saved successfully!"
    
    c2.savePublic(N,E)
    print "\nPublic saved successfully!"
    
    c2.savePrivate(N,D,key)
    print "\nPrivate saved successfully!"
    
    print "\nCheck files for saved keys"
    
    c2.retrievePair(key)
    print "\nPair retrieve successfully!"
    
    c2.retrievePublic()
    print "\nPublic retrieve successfully!"
    
    c2.retrievePrivate(key)
    print "\nPrivate retrievesuccessfully!"


    """
    -----------------------------------------
    
     reprsesentation of crypto_3 methods
     
    -----------------------------------------
    """
    
    print"\n-----------------------------------------"
    print"reprsesentation of crypto_3 methods"
    print"-----------------------------------------"
    
    #generate new keys
    length = 12
    N,E,D = c2.generateRSAkeys(length)
    rsa = c3.RSA()
    
    #plain text for RSA    
    text2 =[0xac, 0xbf, 0x24, 0xc1, 0x28, 0x8b, 0x7d, 0x83, 0x38, 0x53, 0x24, 0x6a, 0x72, 0x8, 0xe, 0x87]

    en = rsa.encrypt(text2,N,E)
    print "\nRSA encryption with n:",N,"and e:",E
    print '[{}]'.format(', '.join(hex(x) for x in en))

    out = rsa.decrypt(en,N,D)
    if text2 == out:
        print "\nRSA decryption with N:",N,"and D:",D
        print '[{}]'.format(', '.join(hex(x) for x in out))
        
        

    """
    -----------------------------------------
    
     reprsesentation of crypto_4 methods
     
    -----------------------------------------
    """
    
    print"\n-----------------------------------------"
    print"reprsesentation of crypto_4 methods"
    print"-----------------------------------------"

    #msg0 = [0xf,0xf,0xe,0x0,0x5,0x4,0xf,0xe,0x7,0xa,0xe,0x0,0xc,0xb,0x6,0xd,0xc,0x6,0x5,0xc,0x3,0xa,0xf,0x9,0xb,0x6,0x1,0xd,0x5,0x2,0x0,0x9,0xf,0x4,0x3,0x9,0x8,0x5,0x1,0xd,0xb,0x4,0x3,0xd,0x0,0xb,0xa,0x5,0x9,0x9,0x7,0x3,0x3,0x7,0xd,0xf,0x1,0x5,0x4,0x6,0x6,0x8,0xe,0xb]
    
    #message for hashing with SHA-256    
    msg1 = "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"     
    
    sha256=c4.SHA()
    
#    out = sha256.shaProcess(msg0)
#    print "\nSHA 256 false:"
#    print '[{}]'.format(', '.join(hex(x) for x in out))
    
    out = sha256.sha256_lib(msg1)
    print "\nSHA 256 with hashlib:"
    print '[{}]'.format(', '.join(hex(x) for x in out))


    """
    -----------------------------------------
    
     reprsesentation of crypto_5 methods
     
    -----------------------------------------
    """
    
    print"\n-----------------------------------------"
    print"reprsesentation of crypto_5 methods"
    print"-----------------------------------------"
    
    #generate new keys
    length = 12
    N,E,D = c2.generateRSAkeys(length)
    
    text2 =[0xac, 0xbf, 0x24, 0xc1, 0x28, 0x8b, 0x7d, 0x83, 0x38, 0x53, 0x24, 0x6a, 0x72, 0x8, 0xe, 0x87, 0x6a, 0x72, 0x8, 0xe, 0x87]
    
    #creates a signature
    signat = c5.signature(text2, N, D)
    print "\nSignature created!"
    
    print "\nTrying to validate signature..."
    if c5.validation(signat, text2, N, E):
        print "\nValidation was successful"
    else:
        print "\nValidation wasn't successful"
    
    """
    -----------------------------------------
    
     reprsesentation of crypto_6 methods
     
    -----------------------------------------
    """
    
    print"\n-----------------------------------------"
    print"reprsesentation of crypto_6 methods"
    print"-----------------------------------------"
    
    #Generate AES key using password but after hashing it
    out =  c6.generateHashedUserKey(pw)
    print "\nPassword: ",'[{}]'.format(', '.join(hex(x) for x in pw))
    print "\nGenerated Key: "
    print '[{}]'.format(', '.join(hex(x) for x in out))