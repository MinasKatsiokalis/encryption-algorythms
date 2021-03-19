"""
----------------------------------  
Minas Katsiokalis
AM: 2011030054 
email: minaskatsiokalis@gmail.com           
----------------------------------
"""

import pickle
from random import randint

class AES(object):

    # valid key size
    keySize = dict(SIZE_128=16)

    # Rijndael S-box
    sbox = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67,
            0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59,
            0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7,
            0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1,
            0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05,
            0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83,
            0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29,
            0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
            0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa,
            0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c,
            0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc,
            0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
            0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
            0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
            0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
            0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4,
            0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
            0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
            0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9,
            0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e,
            0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1,
            0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0,
            0x54, 0xbb, 0x16]

    # Rijndael Inverted S-box
    rsbox =[0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3,
            0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f,
            0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54,
            0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b,
            0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24,
            0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8,
            0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d,
            0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
            0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab,
            0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3,
            0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1,
            0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
            0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6,
            0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9,
            0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d,
            0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0,
            0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07,
            0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60,
            0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f,
            0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5,
            0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b,
            0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55,
            0x21, 0x0c, 0x7d]

    # Rijndael Rcon
    Rcon = [0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
            0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97,
            0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72,
            0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66,
            0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
            0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
            0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
            0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61,
            0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
            0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
            0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc,
            0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5,
            0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a,
            0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d,
            0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c,
            0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
            0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4,
            0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
            0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08,
            0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
            0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d,
            0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2,
            0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74,
            0xe8, 0xcb ]


    """
    -----------------------------------------
                Helpfull functions
    -----------------------------------------
    """
    #returns the Rcon alue
    def getRconValue(self, num):
        """Retrieves a given Rcon Value"""
        return self.Rcon[num]

    #returns the S Box value
    def getSBoxValue(self,num):
        return self.sbox[num]

    #returns the S Box Invert value
    def getSBoxInvert(self,num):
        return self.rsbox[num]

    #rotates the row 1 byte left * number of rotations
    def rotate(self, state, rowPointer, rotations):
        for i in range(rotations):
                state[rowPointer:rowPointer+4] = state[rowPointer+1:rowPointer+4] + state[rowPointer:rowPointer+1]
        return state

    #rotate inverted
    def rotateInv(self, state, rowPointer, rotations):
        for i in range(rotations):
                state[rowPointer:rowPointer+4] = state[rowPointer+3:rowPointer+4] + state[rowPointer:rowPointer+3]
        return state
    
    #rotates a word to the left  
    def rotateWord(self, word):
        return word[1:] + word[:1]

    #Galois Multiplication of byte 'a' and 'b'
    def galois_multiplication(self, a, b):
        p = 0
        for counter in range(8):
            if b & 1: p ^= a
            hi_bit_set = a & 0x80
            a <<= 1
            # keep a 8 bit
            a &= 0xFF
            if hi_bit_set:
                a ^= 0x1b
            b >>= 1
        return p


    """
    -----------------------------------------
                  Key Expansion
    -----------------------------------------
    """
    #Key schedule extendKeyCore.
    def expandKey_Core(self, word, iteration):
        # rotate the 32-bit word 8 bits to the left
        word = self.rotateWord(word)
        # apply S-Box substitution on all 4 parts of the 32-bit word
        for i in range(4):
            word[i] = self.getSBoxValue(word[i])
        # XOR the output of the rcon operation with i to the first part
        # (leftmost) only
        word[0] = word[0] ^ self.getRconValue(iteration)
        return word

    #Rijndael's key expansion.
    def expandKey(self, key, size, expandedKeySize):
        # current expanded keySize, in bytes
        currentSize = 0
        rconIteration = 1
        expandedKey = [0] * expandedKeySize

        # set the 16 bytes of the expanded key to the input key
        for j in range(16):
            expandedKey[j] = key[j]
        currentSize += size

        while currentSize < expandedKeySize:
            # assign the previous 4 bytes to the temporary value temp
            temp = expandedKey[currentSize-4:currentSize]

            # every 16 bytes we apply the extendKeyCore schedule to temp
            if currentSize % size == 0:
                temp = self.expandKey_Core(temp, rconIteration)
                rconIteration += 1

            for m in range(4):
                expandedKey[currentSize] = expandedKey[currentSize - size] ^ temp[m]
                currentSize += 1

        return expandedKey

    #Returns a round key based on the expanded key and the round number
    def createRoundKey(self, expandedKey, roundNum):
        roundKey = [0] * 16
        for i in range(4):
            for j in range(4):
                roundKey[j*4+i] = expandedKey[roundNum + i*4 + j]
        return roundKey


    """
    -----------------------------------------
          The 4 primary operations of AES
    -----------------------------------------
    """

    #Adds (bitwise XOR) the round key to the state
    def addRoundKey(self, state, roundKey):
        for i in range(16):
            state[i] = state[i] ^ roundKey[i]
        return state

    #Substitutes the state bytes with the bytes of Rijndael S-box
    def subBytes(self, state):
        for i in range(16): 
            state[i] = self.getSBoxValue(state[i])
        return state

    #SubBytes inverted
    def subBytesInvert(self, state):
        for i in range(16): 
            state[i] = self.getSBoxInvert(state[i])
        return state

    #Rotates each row, the number of rotations declared by the number of the row (0,1,2,3)
    def shiftRows(self, state):
        for i in range(4):
            state = self.rotate(state, i*4, i)
        return state

    #shiftRows Inverted
    def shiftRowsInvert(self, state):
        for i in range(4):
            state = self.rotateInv(state, i*4, i)
        return state

    #Executes galois multiplication for each column of the block (4x4) 
    def mixColumns(self, state):
        for i in range(4):
            # construct one column by slicing over the 4 rows
            column = state[i:i+16:4]

            # galois multiplication of 1 column of the 4x4 matrix
            mult = [2, 1, 1, 3]
            copy = list(column)
            g = self.galois_multiplication

            column[0] = g(copy[0], mult[0]) ^ g(copy[3], mult[1]) ^ g(copy[2], mult[2]) ^ g(copy[1], mult[3])
            column[1] = g(copy[1], mult[0]) ^ g(copy[0], mult[1]) ^ g(copy[3], mult[2]) ^ g(copy[2], mult[3])
            column[2] = g(copy[2], mult[0]) ^ g(copy[1], mult[1]) ^ g(copy[0], mult[2]) ^ g(copy[3], mult[3])
            column[3] = g(copy[3], mult[0]) ^ g(copy[2], mult[1]) ^ g(copy[1], mult[2]) ^ g(copy[0], mult[3])
           
            # put the values back into the state
            state[i:i+16:4] = column

        return state

    #mixColumns Inverted
    def mixColumnsInvert(self, state):
        for i in range(4):
            # construct one column by slicing over the 4 rows
            column = state[i:i+16:4]

            # galois multiplication of 1 column of the 4x4 matrix
            mult = [14, 9, 13, 11]
        
            copy = list(column)
            g = self.galois_multiplication

            column[0] = g(copy[0], mult[0]) ^ g(copy[3], mult[1]) ^ g(copy[2], mult[2]) ^ g(copy[1], mult[3])
            column[1] = g(copy[1], mult[0]) ^ g(copy[0], mult[1]) ^ g(copy[3], mult[2]) ^ g(copy[2], mult[3])
            column[2] = g(copy[2], mult[0]) ^ g(copy[1], mult[1]) ^ g(copy[0], mult[2]) ^ g(copy[3], mult[3])
            column[3] = g(copy[3], mult[0]) ^ g(copy[2], mult[1]) ^ g(copy[1], mult[2]) ^ g(copy[0], mult[3])
        
            # put the values back into the state
            state[i:i+16:4] = column

        return state

    """
    -----------------------------------------
      AES main and Encrypt/Decrypt functions
    -----------------------------------------
    """

    # Performs the initial operations, the standard round, and the final (for encryption)
    def mainAES(self, state, expandedKey, numberRounds):
        #Initial round #Round = 0
        state = self.addRoundKey(state, self.createRoundKey(expandedKey, 0))
        i = 1
        while i < numberRounds:
            state = self.subBytes(state)
            state = self.shiftRows(state)
            state = self.mixColumns(state)
            state = self.addRoundKey(state, self.createRoundKey(expandedKey, 16*i))
            i += 1
        state = self.subBytes(state)
        state = self.shiftRows(state)
        state = self.addRoundKey(state, self.createRoundKey(expandedKey, 16*numberRounds))
        return state

    #Performs the initial operations, the standard round, and the final (for decryption)
    def mainAESinvert(self, state, expandedKey, numberRounds):
        #Initial round #Round = 10
        state = self.addRoundKey(state,self.createRoundKey(expandedKey, 16*numberRounds))
        i = numberRounds - 1
        while i > 0:
            state = self.shiftRowsInvert(state)
            state = self.subBytesInvert(state)
            state = self.addRoundKey(state, self.createRoundKey(expandedKey, 16*i))
            state = self.mixColumnsInvert(state)
            i -= 1
        state = self.shiftRowsInvert(state)
        state = self.subBytesInvert(state)
        state = self.addRoundKey(state, self.createRoundKey(expandedKey, 0))
        return state
        

    #Encrypts a 128 bit input block of plaintext with the given key
    def encrypt(self, plaintext, key):
        output = [0] * 16
        # the number of rounds
        numberRounds = 0
        # the 128 bit block to encode
        block = [0] * 16
        # set the number of rounds
        if len(key) == self.keySize["SIZE_128"]: 
            numberRounds = 10
        else:
            return None

        # the expanded keySize
        expandedKeySize = 16*(numberRounds+1)

        # Set the block values, for the block:
        # a0,0 a0,1 a0,2 a0,3
        # a1,0 a1,1 a1,2 a1,3
        # a2,0 a2,1 a2,2 a2,3
        # a3,0 a3,1 a3,2 a3,3
        # the mapping order is a0,0 a1,0 a2,0 a3,0 a0,1 a1,1 ... a2,3 a3,3
        #
        # iterate over the columns
        for i in range(4):
            # iterate over the rows
            for j in range(4):
                block[(i+(j*4))] = plaintext[(i*4)+j]
        # expand the key into an 176 bytes key
        expandedKey = self.expandKey(key, len(key), expandedKeySize)

        # encrypt the block using the expandedKey
        block = self.mainAES(block, expandedKey, numberRounds)

        # unmap the block again into the output
        for k in range(4):
            # iterate over the rows
            for l in range(4):
                output[(k*4)+l] = block[(k+(l*4))]
        return output

    #Decrypts a 128 bit input block of ciphertext with the given key
    def decrypt(self, ciphertext, key):
        output = [0] * 16
        # the number of rounds
        numberRounds = 0
        # the 128 bit block to decode
        block = [0] * 16
        # set the number of rounds
        if len(key) == self.keySize["SIZE_128"]: 
            numberRounds = 10
        else: 
            return None

        # the expanded keySize
        expandedKeySize = 16*(numberRounds+1)

        # Set the block values, for the block:
        # a0,0 a0,1 a0,2 a0,3
        # a1,0 a1,1 a1,2 a1,3
        # a2,0 a2,1 a2,2 a2,3
        # a3,0 a3,1 a3,2 a3,3
        # the mapping order is a0,0 a1,0 a2,0 a3,0 a0,1 a1,1 ... a2,3 a3,3

        # iterate over the columns
        for i in range(4):
            # iterate over the rows
            for j in range(4):
                block[(i+(j*4))] = ciphertext[(i*4)+j]
        # expand the key into an 176 bytes key
        expandedKey = self.expandKey(key, len(key), expandedKeySize)
        # decrypt the block using the expandedKey
        block = self.mainAESinvert(block, expandedKey, numberRounds)
        # unmap the block again into the output
        for k in range(4):
            # iterate over the rows
            for l in range(4):
                output[(k*4)+l] = block[(k+(l*4))]
        return output
        
    
    """
    -----------------------------------------
             AES ECB and CBC modes
    -----------------------------------------
    """
        
    #Encryption with AES ECB mode of operation
    def AES_ECBmodeEncryption(self, plaintext, key):

        output = []
        #if plaintext is divided by 16 then we proceed with encryption
        if len(plaintext) % 16 == 0:
            #number of blocks we have to encrypt
            numBlocks = len(plaintext)/16
            #split the list in as many lists as the blocks (1 for each block)
            plaintext = [plaintext[i:i + 16] for i in xrange(0, len(plaintext), 16)]
            for i in range(numBlocks):
                #put all the cipher blocks together as a result
                output = output + self.encrypt(plaintext[i],key)
            return output
        #else we do paddng with 'zeros'
        else:
            #create a list with 'zeros' in order to reach the required block size
            paddingNum = 16-len(plaintext)%16
            padding = [0x00] * paddingNum
            #add them to the plaintext as padding
            plaintext = plaintext + padding
            #number of blocks we have to encrypt
            numBlocks = len(plaintext)/16
            #split the list in as many lists as the blocks (1 for each block)
            plaintext = [plaintext[i:i + 16] for i in xrange(0, len(plaintext), 16)]
            for i in range(numBlocks):
                #put all the cipher blocks together as a result
                output = output + self.encrypt(plaintext[i],key)
            return output

    #Decryption with AES ECB mode of operation
    def AES_ECBmodeDecryption(self, ciphertext, key):
        
        output = []
        #if ciphertext is divided by 16 then we proceed with decryption
        if len(ciphertext) % 16 == 0:
            #number of blocks we have to decrypt
            numBlocks = len(ciphertext)/16
            #split the list in as many lists as the blocks (1 for each block)
            ciphertext = [ciphertext[i:i + 16] for i in xrange(0, len(ciphertext), 16)]
            for i in range(numBlocks):
                #put all the cipher blocks together as a result
                output = output + self.decrypt(ciphertext[i],key)
            return output
        #else we do paddng with 'zeros'
        else:
            #create a list with 'zeros' in order to reach the required block size
            paddingNum =  16-len(plaintext)%16
            padding = [0x00] * paddingNum
            #add them to the ciphertext as padding
            ciphertext = ciphertext + padding
            #number of blocks we have to decrypt
            numBlocks = len(ciphertext)/16
            #split the list in as many lists as the blocks (1 for each block)
            ciphertext = [ciphertext[i:i + 16] for i in xrange(0, len(ciphertext), 16)]
            for i in range(numBlocks):
                #put all the cipher blocks together as a result
                output = output + self.decrypt(ciphertext[i],key)
            return output
            
    #Encryption with AES CBC mode of operation                   
    def AES_CBCmodeEncryption(self, plaintext, key, IV):
        if len(IV) != 16:
            return None
        else:
            output = []
            #if plaintext is divided by 16 then we proceed with decryption
            if len(plaintext) % 16 == 0:
                #number of blocks we have to decrypt
                numBlocks = len(plaintext)/16
                #split the list in as many lists as the blocks (1 for each block)
                plaintext = [plaintext[i:i + 16] for i in xrange(0, len(plaintext), 16)]
                 
                for i in range(numBlocks):
                    for j in range(16):
                        if i == 0:
                            #in first round XOR with Init. Vector
                            plaintext[i][j] = plaintext[i][j] ^ IV[j] 
                        else:
                            #in the rest rounds XOR with previous cipher
                            plaintext[i][j] = plaintext[i][j] ^ output[i*j]
                    #put all the cipher blocks together as a result
                    output = output + self.encrypt(plaintext[i],key)  
                return output
            else:
                #create a list with 'zeros' in order to reach the required block size
                paddingNum =  16-len(plaintext)%16
                padding = [0x00] * paddingNum
                #add them to the plaintext as padding
                plaintext = plaintext + padding
                #number of blocks we have to encrypt
                numBlocks = len(plaintext)/16
                #split the list in as many lists as the blocks (1 for each block)
                plaintext = [plaintext[i:i + 16] for i in xrange(0, len(plaintext), 16)]
                             
                for i in range(numBlocks):
                    for j in range(16):
                        if i == 0:
                            #in first round XOR with Init. Vector
                            plaintext[i][j] = plaintext[i][j] ^ IV[j] 
                        else:
                            #in the rest rounds XOR with previous cipher
                            plaintext[i][j] = plaintext[i][j] ^ output[i*j]
                    #put all the cipher blocks together as a result
                    output = output + self.encrypt(plaintext[i],key)  
                return output
    
    #Decryption with AES CBC mode of operation
    def AES_CBCmodeDecryption(self, ciphertext, key, IV):
        if len(IV) != 16:
            return None
        else:
            output = []
            #if ciphertext is divided by 16 then we proceed with decryption
            if len(ciphertext) % 16 == 0:
                #number of blocks we have to decrypt
                numBlocks = len(ciphertext)/16
                #split the list in as many lists as the blocks (1 for each block)
                ciphertext = [ciphertext[i:i + 16] for i in xrange(0, len(ciphertext), 16)]
                 
                for i in range(numBlocks):
                    output = output + self.decrypt(ciphertext[i],key)
                    for j in range(16):
                        if i == 0:
                            #in first round XOR with Init. Vector
                             output[j] = output[j] ^ IV[j]
                        else:
                            #in the rest rounds XOR with previous cipher
                            output[(16*i)+j] = ciphertext[i-1][j] ^ output[(16*i)+j]
                return output
            else: 
                #create a list with 'zeros' in order to reach the required block size
                paddingNum =  16-len(ciphertext)%16
                padding = [0x00] * paddingNum
                #add them to the ciphertext as padding
                ciphertext = ciphertext + padding
                #number of blocks we have to encrypt
                numBlocks = len(ciphertext)/16
                #split the list in as many lists as the blocks (1 for each block)
                ciphertext = [ciphertext[i:i + 16] for i in xrange(0, len(ciphertext), 16)]
                 
                for i in range(numBlocks):
                    output = output + self.decrypt(ciphertext[i],key)
                    for j in range(16):
                        if i == 0:
                            #in first round XOR with Init. Vector
                             output[j] = output[j] ^ IV[j]
                        else:
                            #in the rest rounds XOR with previous cipher
                            output = ciphertext[i-1][j] ^ output[(16*i)+j]
                return output


    """
    -----------------------------------------
                Keys Generation
    -----------------------------------------
    """
                
    #Generates a random key 16-bytes (128 bits)
    def generateRandomKey(self, keysize):
        key = [0] * 16
        if keysize == 16:
            for i in range(16):
                key[i] = randint(0,255)
            return key
        else:
            return None

    #Generates a key 16-bytes (128 bits) based on user's password
    def generateUserKey(self, password):
        if len(password) == 16:
            key = password
            return key
        elif len(password) < 16:
            key = password
            #create a list with 'zeros' in order to reach the required block size
            paddingNum = 16 % len(password)
            padding = [0x00] * paddingNum
            key = key + padding
            return key
        else:
            return None

    """
    -----------------------------------------
        Read and write key from/to disk
    -----------------------------------------
    """     
    #Saves the key to a file
    def saveKey(self, key):
        key_file = open("key.txt", "w")
        pickle.dump(key, key_file)
        key_file.close()
        
    #Retrieves the key from the file that has been saved into   
    def retrieveKey(self):
        key_file = open("key.txt", "r")
        key =  pickle.load(key_file)
        key_file.close()
        return key     
                    