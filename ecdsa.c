/*
 * ecdsa.c
 *
 *  Created on: Aug 18, 2015
 *      Author: tslld
 */

#include <getopt.h>

#include "ecdsa.h"
#include "ec.h"
#include "ec_point.h"
#include "hash_functions.h"

char* ellipticcurves [] = {
	"secp224k1",
	"secp224r1",
	"secp256k1",
	"secp256r1"
};

void prn_help(void);
void prn_curves(void);
int key_generation(const char* c_name, const char* in_fname, const char* o_fname);
int sig_generation(char* key, char* msg, char *signature);
int sig_verification(char* pub_fname, char* msg, char *sig_fname);

/** ECDSA program
 *
 * 	\param gets a command from keyboard
 *
 */
int main(int argc, char *argv[]) {

	if (argc == 1) {					/* not enough words */
		printf("%s: missing command\n", argv[0]);
		printf("Try '%s --help' or '%s -h' for more information.\n", argv[0], argv[0]);
		return EXIT_SUCCESS;
	}

	int opt = 0;
	char *in_fname = NULL;
	char *out_fname = NULL;
	char *curve_name = NULL;
	char *message = NULL;
	char *priv_fname = NULL;
	char *pub_fname = NULL;
	char *sgn_fname = NULL;
	int gen_flag = 0, sgn_flag = 0, ver_flag = 0, pub_flag = 0;

	while (1) {
		static struct option long_options[] = {
				/* These options don’t set a flag.
	             	We distinguish them by their indices. */
				{"in",			required_argument,  0, 'i'},
				{"out",  		required_argument,  0, 'o'},
				{"genkey",  	no_argument, 		0, 'g'},
				{"pubout",  	no_argument, 		0, 'p'},
				{"name",  		required_argument, 	0, 'n'},
				{"sign",  		required_argument, 	0, 'S'},
				{"verify",    	required_argument, 	0, 'V'},
				{"signature",   required_argument, 	0, 's'},
				{"message",    	required_argument, 	0, 'm'},
				{"curves",		no_argument, 		0, 'c'},
				{"help",		no_argument, 		0, 'h'},
				{0, 0, 0, 0}
		};
		/* getopt_long stores the option index here. */
		int option_index = 0;

		opt = getopt_long(argc, argv, "i:o:g:n:S:V:s:m:l:", long_options, &option_index);
		/* Detect the end of the options. */
		      if (opt == -1)
		        break;

		      switch (opt) {
		      case 0:
		    	  /* If this option set a flag, do nothing else now. */
		    	  if (long_options[option_index].flag != 0)
		            break;
		          printf ("option %s", long_options[option_index].name);
		          if (optarg)
		        	  printf (" with arg %s", optarg);
		          printf ("\n");
		          break;

		        case 'i':
		        	in_fname = optarg;
		        	printf("\nInput option value is the file %s\n", in_fname);
		        	break;

		        case 'o':
		        	out_fname = optarg;
		        	printf("\nOutput option value is file %s\n", out_fname);
		        	break;

		        case 'n':
		        	curve_name = optarg;
		        	printf("\nWe are working on the curve %s\n", curve_name);
		        	break;

		        case 'g':
		        	printf ("Generating a private key \n");
		        	gen_flag = 1;
		        	break;

		        case 'p':
		        	printf ("Generating a public key\n");
		        	pub_flag = 1;
		        	break;

		        case 'S':
		        	printf ("option --sign with value `%s'\n", optarg);
		        	priv_fname = optarg;
		        	sgn_flag = 1;
		        	break;

		        case 'm':
		        	message = optarg;
					printf ("Sign/Verify the message with value `%s'\n", optarg);
					break;

		        case 'V':
		        	printf ("Verifying the signature with public key `%s'\n", optarg);
		        	pub_fname = optarg;
		        	ver_flag = 1;
		        	break;

		        case 's':
		        	printf("Signature is stored in file %s\n", optarg);
		        	sgn_fname = optarg;
		        	break;

		        case 'c':
		        	prn_curves();
		        	break;

		        case 'h':
		        	printf ("Print helps \n");
		        	prn_help();
		        	break;

		        case '?':
		          /* getopt_long already printed an error message. */
		          break;

		        default:
		          abort ();
		        }
	}

	/**	Generate a pair of key
	 * 	if gen_flag = 1, the program generate a private key
	 * 	if pub_flag = 1, the program generate a public key
	 */
	if (gen_flag == 1){
		if (curve_name == NULL) {
			printf("Choose a curve to work \n");
			return 0;
		}
		if (out_fname == NULL) {
			printf("Indicate a file to store private key and system parameters\n");
			return 0;
		}
		if (! key_generation(curve_name, NULL, out_fname)) {
			fprintf(stdout, "Error occurred. Invalid key returned !\n");
			exit(EXIT_FAILURE);
		}
	}


	if (pub_flag == 1){
		if (in_fname == NULL) {
			fprintf(stdout, "Choose a file storing the private key and system parameters \n");
			return 0;
		}
		if (out_fname == NULL) {
			fprintf(stdout, "Indicate a file to store public key and system parameters\n");
			return 0;
		}
		if (!key_generation(NULL, in_fname, out_fname)) {
			fprintf(stdout, "Error occurred. Invalid key returned !\n");
			exit(EXIT_FAILURE);
		}
	}

	/**	Generate a signature.
	 * 	Need to provide a file or message to sign; and a file to store signature generated
	 */
	if (sgn_flag == 1){

		if (message == NULL) {
			printf("Give a file / message needed to sign \n");
			return 0;
		}
		if (sgn_fname == NULL) {
			printf("Indicate a file to store the signature \n");
			return 0;
		}
		if (! sig_generation(priv_fname, message, sgn_fname)) {
			fprintf(stdout, "Error occurred. Invalid signature returned !\n");
			exit(EXIT_FAILURE);
		}
	}

	/**	Verify a signature.
	 * 	Need to provide a file or message to sign; and a file to store signature generated
	 */
	if (ver_flag == 1){
		if (pub_fname == NULL) {
			printf("Indicate the file storing the public key and system parameters \n");
			return 0;
		}
		if (sgn_fname == NULL) {
			printf("Indicate a file to store the signature \n");
			return 0;
		}
		if (message == NULL) {
			printf("Give a file / message needed to verify \n");
			return 0;
		}
		if (! sig_verification(pub_fname, message, sgn_fname) ) {
			fprintf(stdout, "Error occurred. Invalid verification !\n");
			exit(EXIT_FAILURE);
		}
	}

	return 1;
}

/** Print out buit-in commands
 */
void prn_help(void) {
	//Short usage introduction
	printf("Usage: ecdsa <command> [options]\nGenerate public key, sign and verify messages using the elliptic curve digital signature algorithm.\n\n");

	//List all commands and a short description
	printf("Commands:\n");
	printf(" --curves 				or  --c			The full list of built-in curves \n");
	printf(" --genkey				or  --g			Generate a private key\n");
	printf(" --pubout				or  --p			Generate a public key\n");
	printf(" --sign	[key]			or  --S	 		Sign a message\n");
	printf(" --verify [key]			or 	--V		    Verify signature\n");
	printf(" --signature [filename]	or 	--s		    Indicate a file to store signature\n");
	printf(" --in 	[filename]		or 	--i		    Indicate a file to store  signature\n");
	printf(" --out 	[filename]		or 	--o		    Indicate a file to store  signature\n");
	printf(" --help       			or 	--h			Display help.\n");

	//List all options and a short description
	printf("\nOptions:\n");

	return;
}


/** Print out the list of curves buit-in
 *
 */
void prn_curves() {
	int n = sizeof(ellipticcurves)/sizeof(ellipticcurves[0]);

	fprintf(stdout, "Elliptic curves built-in the program consist of:\n");

	for (int i = 0; i < n; i++) {
		fprintf(stdout, "%s\n", ellipticcurves[i]);
	}
}

/**	Generate system parameters and a pair of key
 * 	\param
 * 	\param
 * 	\param
 *
 * 	\return
 */
int key_generation(const char* c_name, const char* in_fname, const char* o_fname) {

	// Declare variables
	FILE *ifp = NULL;
	FILE *ofp = NULL;
	ec_key eckey = NULL;
	char curve[9];
	char priv_str[600];
	int genpub = 0;
	int ok = 0;

	// Open file to write the value of private/public key generated
	if (o_fname != NULL ) {
		ofp = fopen(o_fname, "w");
		if(ofp == NULL) {
			fprintf(stderr, "Can't open output file: %s\n", o_fname);
			return (ok); //exit(EXIT_FAILURE);
		}
	} else {
		fprintf(stderr, "Need to provide an output file name to store private or public key \n");
		return (ok); //exit(2);
	}

	if(c_name != NULL) { // Curve provided to generate a private key
		strcpy(curve, c_name);
		genpub = 0;
	} else { // A file storing private key need to be provided
		if (in_fname == NULL ) { // No file name provided to open
			fprintf(stderr, "Need to provide the input file storing the private key \n");
			return (ok);
		}else {
			ifp = fopen(in_fname, "r");
			if(ifp == NULL) {
				fprintf(stderr, "Can't open input file %s to read the private key \n", in_fname);
				return (ok);
			} else {
				if (fscanf(ifp, "%s", curve) == EOF) {
					fprintf(stderr, "Can't get the curve name from file %s \n", in_fname);
					exit(EXIT_FAILURE);
				}
				if (fscanf(ifp, "%s", priv_str) == EOF) {
					fprintf(stderr, "Can't get the private key from file %s \n", in_fname);
					return (ok);
				}
				genpub = 1;
			}
		}

	}

	eckey = ec_key_init_by_curve_name(curve);

	if (eckey == NULL) {
		fprintf(stderr, "Curve %s was not built-in the program \n", c_name);
		return (ok);//exit(2);
	}

	if (genpub == 1)
		mpz_set_str(eckey->priv_key, priv_str, 16);



	if (! ec_key_generate_key(eckey, genpub)) {
		fprintf(stderr, "Unexpected error happen while generating a pair of key !\n");
		return (ok);
	}

	if (genpub == 0) {
		fprintf(ofp, "%s\n", curve);
		mpz_out_str(ofp, 16, eckey->priv_key);

	} else {
		if (! ec_key_check_public_key(eckey->pub_key, eckey->group)) {
			fprintf(stderr, "Invalid public key generated !\n");
			return (ok);
		}
		fprintf(ofp, "%s\n", curve);
		mpz_out_str(ofp, 16, eckey->pub_key->x);
		fprintf(ofp, "\n");
		mpz_out_str(ofp, 16, eckey->pub_key->y);
		//ec_point_print_fp(ofp, eckey->pub_key);
	}

	ok = 1;

	// Close files
	if (ifp != NULL)
		fclose(ifp);
	if (ofp != NULL)
		fclose(ofp);

	// Release memory
	ec_key_free(eckey);
	return (ok);
}


/*
 * Generate a signature for a given message
 *
 * @input: message m, private key sk
 *
 * @return: signature s
 *
 */

int sig_generation(char* key, char* msg, char *signature) {

	// Declare variables
	FILE *ifp = NULL;
	FILE *ofp = NULL;
	char curve[9];
	char priv_str[600];
	int ok = 0;

	// Open file to write the value of signature generated
	if (signature != NULL ) {
		ofp = fopen(signature, "w");
		if(ofp == NULL) {
			fprintf(stderr, "Can't open output file: %s\n", signature);
			return (ok); //exit(EXIT_FAILURE);
		}
	} else {
		fprintf(stderr, "Need to provide an output file name to store private or public key \n");
		return (ok); //exit(2);
	}

	// Load system parameters & private key for the file "key"
	if (key == NULL ) { // No file name provided to open
		fprintf(stderr, "Need to provide the input file storing the private key \n");
		return (ok); //exit(EXIT_FAILURE);
	}else {
		ifp = fopen(key, "r");
		if(ifp == NULL) {
			fprintf(stderr, "Can't open input file %s to read the private key \n", key);
			return (ok); //exit(EXIT_FAILURE);
		} else {
			if (fscanf(ifp, "%s", curve) == EOF) {
				fprintf(stderr, "Can't get the curve name from file %s \n", key);
				return (ok); //exit(EXIT_FAILURE);
			}
			if (fscanf(ifp, "%s", priv_str) == EOF) {
				fprintf(stderr, "Can't get the private key from file %s \n", key);
				return (ok); //exit(EXIT_FAILURE);
			}
		}
	}
	// Get ec_key from the curve and private key given
	ec_key eckey = ec_key_init_by_curve_name(curve);
	if (eckey == NULL) {
		fprintf(stderr, "Curve %s was not built-in the program \n", curve);
		return (ok); //exit(EXIT_FAILURE);
	}

	mpz_set_str(eckey->priv_key, priv_str, 16);

	// Get right curve
	// mpz_out_str(stdout, 16, eckey->group->order);
	// printf("\n");

	// Get and hash message
	char *dgst = get_dgst_224(msg); //malloc(SHA224_DIGEST_STRING_LENGTH);
	/*
	output224[SHA224_DIGEST_STRING_LENGTH] = '\0';
	FILE *msg_fp = NULL;
	SHA224_Context ctx;
	uchar buf[1000];
	uchar sha224sum[SHA224_DIGEST_LENGTH];
	int i;

	if (!(msg_fp = fopen( msg, "rb"))) {
		output224 = sha224(msg);
	} else {
		sha224_init( &ctx );

		while ((i = fread( buf, 1, sizeof(buf), msg_fp )) > 0) {
			sha224_update(&ctx, buf, i);
		}

		sha224_final(&ctx, sha224sum);

		for(i = 0; i < SHA224_DIGEST_LENGTH ; ++i) {
			sprintf(output224 +i*2, "%02x", sha224sum[i]);
		}
	}*/

	// Sign the message with the private key
	int digst_len = strlen(dgst);
	// printf("Digest length is %d !\n", digst_len);
	mpz_t kinv, rp;
	mpz_init(kinv); mpz_init(rp);

	if (!ecdsa_sign_setup(eckey, kinv, rp)) {
		fprintf(stdout, "Error occurred during generating signature !\n");
		return (ok);
	}

	ecdsa_sig sig = ecdsa_sign(dgst, digst_len, kinv, rp, eckey);

	if (sig == NULL) {
		fprintf(stdout, "Error occurred during generating signature !\n");
		return (ok);
	}


	ecs_print_fp(ofp, sig);

	ok = 1;

	// Close files
	if (ifp != NULL)
		fclose(ifp);
	if (ofp != NULL)
		fclose(ofp);

	free(dgst);
	mpz_clear(kinv); mpz_clear(rp);

	ec_key_free(eckey);
	ecs_free(sig);

	return (ok);
}



/** Verify a given signature *
 *	\param	pub_fname	file name storing public key information
 *	\param 	msg			file of message need to verify
 *	\param 	sig_fname	file storing signature
 *
 * 	\return -1	if an error occur; 0 if signature is invalide; 1 if signature is valid *
 */
int sig_verification(char* pub_fname, char* msg, char *sig_fname) {
	// Declare variables
	int ok = 0;
	FILE *pub_fp = NULL;
	FILE *sig_fp = NULL;

	// Get and hash message
	char *dgst = get_dgst_224(msg); // malloc(SHA224_DIGEST_STRING_LENGTH);

	/*
	output224[SHA224_DIGEST_STRING_LENGTH] = '\0';
	FILE *msg_fp = NULL;
	SHA224_Context ctx;
	uchar buf[1000];
	uchar sha224sum[SHA224_DIGEST_LENGTH];
	int i;

	if (!(msg_fp = fopen( msg, "rb"))) {
		output224 = sha224(msg);
	} else {
		sha224_init( &ctx );

		while ((i = fread( buf, 1, sizeof(buf), msg_fp )) > 0) {
			sha224_update(&ctx, buf, i);
		}

		sha224_final(&ctx, sha224sum);

		for(i = 0; i < SHA224_DIGEST_LENGTH ; ++i) {
			sprintf(output224 +i*2, "%02x", sha224sum[i]);
		}
	}
	printf("Message digest is signed is %s \n", output224); */

	int digst_len = strlen(dgst);

	// Open the signature file to read
	if (sig_fname != NULL ) {
		sig_fp = fopen(sig_fname, "r");
		if(sig_fp == NULL) {
			fprintf(stderr, "Can't open output file: %s\n", sig_fname);
			return (ok);
		}
	} else {
		fprintf(stderr, "Need to provide a signature file name to read \n");
		return (ok);
	}

	// // Get and analyze the signature (an ecdsa_sig structure)
	char str[600];
	mpz_t R, S;
	if (fscanf(sig_fp, "%s", str) == EOF) {
		fprintf(stderr, "Can't get the curve name from file %s \n", sig_fname);
		return (ok);
	}
	if (fscanf(sig_fp, "%s", str) == EOF) {
		fprintf(stderr, "Can't get the curve name from file %s \n", sig_fname);
		return (ok);
	}

	if (fscanf(sig_fp, "%s", str) == EOF) {
		fprintf(stderr, "Can't get the curve name from file %s \n", sig_fname);
		return (ok);
	} else {
		mpz_init_set_str(R, str, 16);
		//mpz_out_str(stdout, 16, R);
	}


	if (fscanf(sig_fp, "%s", str) == EOF) {
		fprintf(stderr, "EOF of file %s \n", sig_fname);
		return (ok);
	} else {
		mpz_init_set_str(S, str, 16);
		//mpz_out_str(stdout, 16, S);
	}

	ecdsa_sig sig = ecs_init_set(R, S);
	mpz_clear(R); mpz_clear(S);

	/** Load system parameters and public key
	 *
	 */
	ec_group group = NULL;
	ec_point pubkey = NULL;

	if (pub_fname == NULL ) { // No file name provided to open
		fprintf(stderr, "Need to provide the input file storing the private key \n");
		return (ok);
	}else {
		pub_fp = fopen(pub_fname, "r");
		if(pub_fp == NULL) {
			fprintf(stderr, "Can't open input file %s to read the private key \n", pub_fname);
			return (ok);
		} else {
			char str_X[600], str_Y[600];
			char curve[9];
			if (fscanf(pub_fp, "%s", curve) == EOF) {
				fprintf(stderr, "Can't get the curve name from file %s \n", pub_fname);
				return (ok);
			}
			if (fscanf(pub_fp, "%s", str_X) == EOF) {
				fprintf(stderr, "Can't get the curve name from file %s \n", pub_fname);
				return (ok);
			}
			if (fscanf(pub_fp, "%s", str_Y) == EOF) {
				fprintf(stderr, "Can't get the private key from file %s \n", pub_fname);
				return (ok);
			}

			// Get ec_group from the curve given
			group = ec_group_init_by_curve_name(curve);
			if (group == NULL) {
				fprintf(stderr, "Curve %s was not built-in the program \n", curve);
				return (ok);
			}

			// Get public key
			mpz_t X, Y;
			mpz_init_set_str(X, str_X, 16); mpz_init_set_str(Y, str_Y, 16);
			pubkey = ec_point_init_set_mpz(X, Y);

			// Verify the validation of the public key
			if (! ec_key_check_public_key(pubkey, group)) {
				fprintf(stderr, "Public key point given is failed to verify !\n");
				return (ok);
			}
			mpz_clear(X); mpz_clear(Y);
		}
	}

	// Verify the signature with the public key
	if (ecdsa_verify(dgst, digst_len, sig, group, pubkey)) {
		fprintf(stdout, "Signature is valid.\n");

		printf("Signature is :\n");
		mpz_out_str(stdout, 16, sig->r);
		printf(" : ");
		mpz_out_str(stdout, 16, sig->s);
		printf("\n");

		return 1;
	}
	else {
		fprintf(stdout, "Signature is NOT valid!\n");
		printf("Signature is :\n");
		mpz_out_str(stdout, 16, sig->r);
		printf(" : ");
		mpz_out_str(stdout, 16, sig->s);
		printf("\n");

		return 0;
	}

	ok = 1;

	// Close files
	if (sig_fp != NULL)
		fclose(sig_fp);
	if (pub_fp != NULL)
		fclose(pub_fp);

	free(dgst);
	ec_group_free(group);
	ec_point_free(pubkey);

	return (ok);
}

