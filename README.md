This is Readme file for the software "Secure ECDSA Implementation". This file will explain how the program work. The main program is ecdsa


I. How to compile the program

Go to the directory containing the Makefile and 'make'

command: make


II. Functionality of the program

1. Display a list of curves supported in the program:

command: ./ecdsa --curves or ./ecdsa --c

input: No input requried
output: The list of standardized elliptic curves supported in the program. 

Note that: The current implementation supports 2 prime curves at 224 bit: secp224k1, secp224r1; and 2 prime curves at 256 bit security level: secp256r1, secp256k1.
 
2. Generate a private key:

command: ./ecdsa --genkey --name secp256r1 --out priv256.pem

parameters: --genkey (or --g), --name (or –n), --out (or --o)

input: 	- name: a curve name that the algorithms will work on, eg., NIST prime curve at 256 bit security level: secp256r1

output: 	- out: file storing the private key and system parameters., eg., priv256.pem

Note that: the output file contains 2 lines: the first line indicates the elliptic curve used, and the second line indicate the value of the private key

3. Given a private key, generate a public key:

command: ./ecdsa --pubout --in priv256.pem --out pub256.pem

parameters: --pubout (or --p), --in (or –i), --out (or –o)

input: 	- in: a file storing the private key and system information, eg, priv256.pem


output: 	- out: file storing the public key and system parameters., eg., pub256.pem

Note that: the output file contains 2 lines: the first line indicates the elliptic curve used, and the second line indicate the value of the public key


4. Given a private key, generate a signature:

command: ./ecdsa --sign priv256.pem --message adc.dat --signature sig256.pem

parameters: --sign (or --S), --message (or –m), --signature (or –s)

input: 	- sign: a file storing the private key and system information, eg, priv256.pem
		- message: a message or a file needed to sign, eg, abc.dat


output: 	- signature: file storing the generated signature, eg., sig256.pem



5. Given a signature, verify the validation:

command: ./ecdsa --verify pub256.pem --message adc.dat --signature sig256.pem

parameters: --verify (or --V), --message (or –m), --signature (or –s)

input: 	- verify: a file storing the public key and system information, eg, pub256.pem
		- message: a message or a file needed to verify, eg, abc.dat


output: 	- signature: file storing the signature corresponding with the signed message, eg., sig256.pem

Note that: a signature consists of 2 values (big integers): (r, s). The output file stores these values.
 

6. Display a list of command supported in the program:

command: ./ecdsa --help or ./ecdsa --h

input: No input requried
output: The list of command supported in the program



III. How to test the program
The software provides a number of tests to verify the functionality of the program:

1. Test finite field : given 2 values, verify basic finite field operations: addition, subtraction, inversion, multiplication, exponentiation

command: ./fftest
	
2. Test EC operations: given curves, points; verify basic elliptic curves operations: test order, point on curve, addition, doubling, inversion, multiplication

command: ./ectest

3. Test signature algorithms: verify signature algorihms: key generation, signature generation and signature verification.

command: ./ecstest

4. Test hash funcions : verify the validation of hash functions implemented in the program: SHA1, SHA2

command: ./hashtest




IV. List of files

The distribution media contains the following files:

1. Executable files:

	Makefile		- the 'make' file compiling the program
	ecdsa        	- the main program   
	fftest       	- test the finite field operations
	ecstest 		- test signatures algorithms: Key generation; signature 					  generation and signature verification 
	ectest		- test elliptic curves operations 
	hashtest          - test hash functions implemented: SHA1, SHA2


2. Data files: the two following files are used to test functionality of hash functions
 
	abc.dat
	abcdbcde.dat 



3. Source files: C source files. The software is implemented hierarchically as follows:


a) Finite field level:

	 field_ops.c	- implement finite field operations


b) Elliptic curve level:

Elliptic curves implementation including: declare, initialize, free, print, copy, … 
	ec_free.c		
	ec_inits.c     
	ec_prn.c
	ec_cpy.c       
	ec_dup.c
	ec_lib.c     

Points operations including: point addition, doubling, multiplication, compress, … 
	ec_ops.c     
	ecp_compress.c  
	ecp_inverse.c               
	ecp_prn.c
	ecp_convers.c   
	ecp_is_inverse.c	
	ecp_cpy.c       
	ecp_is_on_curve.c           
	ecp_free.c      
	ecp_lib.c                       
	ecp_cmp.c    
	ecp_inits.c     

	ecp_dup.c       
	ecp_is_point_at_infinity.c

c) Signature level:

	ecdsa.c		- main program 

Implemented functions involving key generation:

	eck_inits.c    
	eck_lib.c
	eck_prn.c
	eck_cpy.c
	eck_dup.c       
	eck_free.c                   
	ecs_genkey.c  

Implemented functions involving signature generation: 

	ecs_free.c
	ecs_cpy.c   
	ecs_prn.c
	ecs_dup.c   
	ecs_sgn.c 
	ecs_inits.c 
	ecs_cmp.c   
	ecs_lib.c 

Verifying a signature:
	ecs_vrf.c

d) Hash functions and other useful functions:

	hash_functions.c  	- Implement hash functions: SHA1, SHA2
	get_dgst.c 			- Generate a hash digest from a given file
	data_parser.c         	- Analyze key pair given in a file
	utils.c			- Implement useful tools used in the software

e) Test files:
	
	fftest.c			- Test finite field 
	ecstest.c			- Test signature algorithms
	hashtest.c			- Test hash funcions 
	ectest.c			- Test EC operations
                  

f) Header files:

	parameters.h   
	utils.h
	ecdsatest.h
	field_ops.h
	ec.h
	ecdsa.h
	ec_point.h
	hash_functions.h

g) Testing Output files:

	sig.pem		- Store signature
	pub.pem		- Store public key information 
	priv.pem		- Store private key information
