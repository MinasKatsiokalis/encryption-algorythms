"""
----------------------------------  
Minas Katsiokalis
AM: 2011030054 
email: minaskatsiokalis@gmail.com           
----------------------------------
"""

import hashlib
import array

class SHA(object): 

	#Initialize hash values: (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
	H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

	#Initialize array of round constants:(first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311):
	K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

	"""
	-----------------------------------------
	 		 Rotate right function
	-----------------------------------------
	"""

	def rotr(self, x, y):
		return ((x >> y) | (x << (32-y))) & 0xFFFFFFFFL

	"""
	-----------------------------------------
	 		   SHA 256 functions
	-----------------------------------------
	"""

	def sha256_lib(self,message):

		hash_out = hashlib.sha256(message).hexdigest()
		hash_out = hash_out.decode("hex")

		hash_out = array.array('B', hash_out)
		hash_out = map(None, hash_out)

		return hash_out


	def shaProcess(self,message):

		blocks = len(message)/64
		message = [message[i:i + 64] for i in xrange(0, len(message), 64)]
		

		for b in range(blocks):
			w = [0]*64
			for i in range(0,16):
				w[i]=message[b][i]

			for i in range(16,64):
				s0 = (self.rotr(w[i-15],7)) ^ (self.rotr(w[i-15],18)) ^ (w[i-15] >> 3)
				s1 = (self.rotr(w[i-2],17)) ^ (self.rotr(w[i-2], 19)) ^ (w[i-2] >> 10)
				w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFFL

			a = self.H[0]
			b = self.H[1]
			c = self.H[2]
			d = self.H[3]
			e = self.H[4]
			f = self.H[5]
			g = self.H[6]
			h = self.H[7]

			for i in range(64):
				s1 = self.rotr(e, 6) ^ self.rotr(e, 11) ^ self.rotr(e, 25)
				ch = (e & f) ^ ((~e) & g)
				temp1 = h + s1 + ch + self.K[i] + w[i]
				s0 = self.rotr(a, 2) ^ self.rotr(a, 13) ^ self.rotr(a, 22)
				maj = (a & b) ^ (a & c) ^ (b & c)
				temp2 = s0 + maj

				h = g	
				g = f
				f = e
				e = (d + temp1) & 0xFFFFFFFFL
				d = c
				c = b
				b = a
				a = (temp1 + temp2) & 0xFFFFFFFFL

			self.H[0] = (self.H[0] + a) & 0xFFFFFFFFL
			self.H[1] = (self.H[1] + b) & 0xFFFFFFFFL
			self.H[2] = (self.H[2] + c) & 0xFFFFFFFFL
			self.H[3] = (self.H[3] + d) & 0xFFFFFFFFL
			self.H[4] = (self.H[4] + e) & 0xFFFFFFFFL
			self.H[5] = (self.H[5] + f) & 0xFFFFFFFFL
			self.H[6] = (self.H[6] + g) & 0xFFFFFFFFL
			self.H[7] = (self.H[7] + h) & 0xFFFFFFFFL

			digest = []
			digest.append(self.H[1])
			digest.append(self.H[2])
			digest.append(self.H[3])
			digest.append(self.H[4])
			digest.append(self.H[5])
			digest.append(self.H[6])
			digest.append(self.H[7])

		return digest





		




