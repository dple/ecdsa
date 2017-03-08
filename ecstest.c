/*
 * ecstest.c
 *
 *  Created on: Nov 20, 2015
 *      Author: tslld
 */

#include "ecdsa.h"
#include "ec.h"
#include "ec_point.h"
#include "field_ops.h"
#include "hash_functions.h"

struct ecdsa_params {
	const char* name;
	const char *p, *a, *b, *Gx, *Gy, *order, *d, *Qx, *Qy;		// d private key, Q public key
	const char *k, *kinv, *Rx, *Ry, *r, *msg, *dgst, *e, *s;	// parameters for signature generation test
	const char *w, *u1, *u2;									// parameters for signature verification test
};

/*
 * NIST test vectors for ECDSA digital algorithm
 * https://www.nsa.gov/ia/_files/ecdsa.pdf
 * http://csrc.nist.gov/groups/STM/cavp/documents/dss/186-3ecdsatestvectors.zip
 *
 */
static const struct ecdsa_params ecs_params[] = {
	{
	 /* NIST P-224 */
	 "secp224r1",
	 /* p */
	 "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001",
	 /* a */
	 "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE",
	 /* b */
	 "B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4",
	 /* Gx */
	 "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21",
	 /* Gy */
	 "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34",
	 /* order */
	 "FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D",
	 /* For key generation test */
	 /* d -- private key */
	 "16797b5c0c7ed5461e2ff1b88e6eafa03c0f46bf072000dfc830d615",
	 /* Qx, Q = d * G -- public key */
	 "605495756e6e88f1d07ae5f98787af9b4da8a641d1a9492a12174eab",
	 /* Qy */
	 "f5cc733b17decc806ef1df861a42505d0af9ef7c3df3959b8dfc6669",
	 /* For signature generation test */
	 /* k */
	 "d9a5a7328117f48b4b8dd8c17dae722e756b3ff64bd29a527137eec0",
	 /* kinv */
	 "26D627DA513D5F6663EC209F037334695111BF1C17B02A996A973232",
	 //"95D070D79F52FCC7F816A19654DE01BF63CBD56424FD9489959F0E48",
	 /* Rx, R = k * G */
	 "2FC2CFF8CDD4866B1D74E45B07D333AF46B7AF0888049D0FDBC7B0D6",
	 /* Ry */
	 "B0CC33624FB2A486FDCAF0194A84E4CCB174EEE6703F8A26F80199A2",
	 /* r = Rx mod order */
	 "2fc2cff8cdd4866b1d74e45b07d333af46b7af0888049d0fdbc7b0d6",
	 /* M -- Message */
	 //"This is only a test message. It is 48 bytes long",
	 "699325d6fc8fbbb4981a6ded3c3a54ad2e4e3db8a5669201912064c6" \
	 "4e700c139248cdc19495df081c3fc60245b9f25fc9e301b845b3d703" \
	 "a694986e4641ae3c7e5a19e6d6edbf1d61e535f49a8fad5f4ac26397" \
	 "cfec682f161a5fcd32c5e780668b0181a91955157635536a22367308" \
	 "036e2070f544ad4fff3d5122c76fad5d",
	 /* H(M) - SHA-224 */
	 "3f57f4397a09491be9e6239988899277662c3c9bd5fdfcdf728fe031",
	 /* e -- convert bit string of H(M) to an integer */
	 "6670856552910757781904163985201137851016622044111439802104944779313",
	 /* s = (kinv * (e + d * r)) mod order */
	 "486A13ABE520C55EC2A613DBD4BF69F9C09E5CCDA6ABD69031D8C73",
	 /* Parameters for verification -- Compute from magma */
	 /* w = s^{-1} mod order */
	 "C309985ED90473F731E93E06F6C1D8056CF9D919343735694DBF48A6",
	 /* u1 = e * w mod order */
	 "629A226F009104BBE288AE31C634F9551D93DDEBDF005DD4164CCC43",
	 /* u2 = r * w mod order */
	 "7CDE86B1FE0007A0ED0BFF5B5892B791A15417AA29B3E08DA7B3952F",
	},
	{
     /* NIST P-256 */
     "secp256r1",
     /* p */
	 "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
     /* a */
	 "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
     /* b */
	 "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
	 /* Gx, G base point */
	 "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
	 /* Gy */
	 "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
	 /* order */
	 "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
	 /* For key generation test */
	 /* d -- private key */
	 "70a12c2db16845ed56ff68cfc21a472b3f04d7d6851bf6349f2d7d5b 3452b38a",
     /* Qx, Q = d * G -- public key */
     "8101ece47464a6ead70cf69a6e2bd3d88691a3262d22cba4f7635eaff26680a8",
     /* Qy */
     "d8a12ba61d599235f67d9cb4d58f1783d3ca43e78f0a5abaa624079936c0c3a9",
	 /* For signature generation test */
	 /* k */
	 "580ec00d856434334cef3f71ecaed4965b12ae37fa47055b1965c7b134ee45d0",
	 /* kinv */
	 "6a664fa115356d33f16331b54c4e7ce967965386c7dcbf2904604d0c132b4a74",
	 /* Rx, R = k * G */
	 "7214bc9647160bbd39ff2f80533f5dc6ddd70ddf86bb815661e805d5d4e6f27c",
	 /* Ry */
	 "8b81e3e977597110c7cf2633435b2294b72642987defd3d4007e1cfc5df84541",
	 /* r = Rx mod order */
	 "7214bc9647160bbd39ff2f80533f5dc6ddd70ddf86bb815661e805d5d4e6f27c",
	 /* M -- Message */
	 "This is only a test message. It is 48 bytes long",
	 /* H(M) -- SHA-256 */
	 "7c3e883ddc8bd688f96eac5e9324222c8f30f9d6bb59e9c5f020bd39ba2b8377",
	 /* e -- convert bit string of H(M) to an integer */
	 //"7C3E883DDC8BD688F96EAC5E9324222C8F30F9D6BB59E9C5F020BD39BA2B8377",
	 "56197278047627432394583341962843287937266210957576322469816113796290471232375",
	 /* s = (kinv * (e + d * r)) mod order */
	 "7d1ff961980f961bdaa3233b6209f4013317d3e3f9e1493592dbeaa1af2bc367",
	 /* Parameters for verification */
	 /* w = s^{-1} */
	 "d69be75f67ee5394cabb6c286f3610cf62d722cba9eea70faee770a6b2ed72dc",
	 /* u1 = e * w */
	 "bb252401d6fb322bb747184cf2ac52bf8d54b95a1515062a2f6141f2e2092ed8",
	 /* u2 = r * w */
	 "aae7d1c7f2c232dfc641948af3dba141d4de8634e571cf84c486301b510cfc04",
	},
	{
	 /* NIST P-384 */
	 "secp384r1",
	 /* p */
	 "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
	 /* a */
	 "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC",
	 /* b */
	 "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
	 /* Gx, G base point */
	 "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
	 /* Gy */
	 "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
	 /* order */
	 "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
	 /* For key generation test */
	 /* d -- private key */
	 "c838b85253ef8dc7394fa5808a5183981c7deef5a69ba8f4f2117ffea39cfcd90e95f6cbc854abacab701d50c1f3cf24",
	 /* Qx, Q = d * G -- public key */
	 "1fbac8eebd0cbf35640b39efe0808dd774debff20a2a329e91713baf7d7f3c3e81546d883730bee7e48678f857b02ca0",
	 /* Qy */
	 "eb213103bd68ce343365a8a4c3d4555fa385f5330203bdd76ffad1f3affb95751c132007e1b240353cb0a4cf1693bdf9",
	 /* For signature generation test */
	 /* k */
	 "dc6b44036989a196e39d1cdac000812f4bdd8b2db41bb33af51372585ebd1db63f0ce8275aa1fd45e2d2a735f8749359",
	 /* kinv */
	 "7436f03088e65c37ba8e7b33887fbc87757514d611f7d1fbdf6d2104a297ad318cdbf7404e4ba37e599666df37b8d8be",
	 /* Rx, R = k * G */
	 "a0c27ec893092dea1e1bd2ccfed3cf945c8134ed0c9f81311a0f4a05942db8dbed8dd59f267471d5462aa14fe72de856",
	 /* Ry */
	 "855649409815bb91424eaca5fd76c97375d575d1422ec53d343bd33b847fdf0c11569685b528ab25493015428d7cf72b",
	 /* r = Rx mod order */
	 "a0c27ec893092dea1e1bd2ccfed3cf945c8134ed0c9f81311a0f4a05942db8dbed8dd59f267471d5462aa14fe72de856",
	 /* M -- Message */
	 "This is only a test message. It is 48 bytes long",
	 /* H(M) -- SHA-384 */
	 "b9210c9d7e20897ab86597266a9d5077e8db1b06f7220ed6ee75bd8b45db37891f8ba5550304004159f4453dc5b3f5a1",
	 /* e -- convert bit string of H(M) to an integer */
	 //"b9210c9d7e20897ab86597266a9d5077e8db1b06f7220ed6ee75bd8b45db37891f8ba5550304004159f4453dc5b3f5a1",
	 "28493976155450475404302482243066463769180620629462008675793884393889401828800663731864240088367206094074919580333473",
	 /* s = (kinv * (e + d * r)) mod order */
	 "20ab3f45b74f10b6e11f96a2c8eb694d206b9dda86d3c7e331c26b22c987b7537726577667adadf168ebbe803794a402",
	 /* Parameters for verification */
	 /* w = s^{-1} */
	 "1798845cd0a6cea5327c501a71a4baf2f7be882cfbc303750a7c861af8fe8225467a257f5bf91a4aaa5a79a8637d218a",
	 /* u1 = e * w */
	 "6ce25649d42d223e020c11140fe772326612bb11b686d35ee98ed4550e0635d9dd3a2afbca0cf2c4baedcd23313b189e",
	 /* u2 = r * w */
	 "f3b240751d5d8ed394a4b5bf8e2a4c0e1e21aa51f2620a08b8c55a2bc334c9689923162648f06e5f4659fc526d9c1fd6",
	},
};

/** Key Pair Generation Test. Recalculates the public key, Q’, from the private key supplied.
 * 	The value Q’ is then compared to the supplied value Q.
 * 	\param
 * 	\param
 * 	\param
 * 	\param
 *
 */
static int ecs_keygen_test(ec_point G, ec_point Q, mpz_t d, ec_group ec) {
	int ok = 0;
	fprintf(stdout, "\nverifying the generated public key ...\n");

	ec_point Rop = ecp_mul_atomic(G, d, ec);

	if (! ec_key_check_public_key(Rop, ec)) {
		fprintf(stderr, "failed !\n");
		goto err;
	} else {
		fprintf(stdout, "Public Key Validation Test -- passed ! \n");
		ok = 1;
	}

	if (ec_point_cmp(Rop, Q, ec->field)) {
		fprintf(stdout, "Key Pair Generation Test -- passed ! \n");
		ok = 1;
	} else
		fprintf(stdout, "failed ! \n");

	err:
	ec_point_free(Rop);

	return (ok);
}


static void ecdsa_single_test(const struct ecdsa_params *test) {

	fprintf(stdout, "\n-------------------------------------------------------------");
	fprintf(stdout, "\nECDSA Tests with the curve %s. ", test->name);
	fprintf(stdout,
			"This curve is defined by Weierstrass equation\n     y^2 = x^3 + a*x + b  (mod 0x");
	fprintf(stdout, "%s)\n\t a = 0x%s\n\t b = 0x%s\n", test->p, test->a, test->b);

	fprintf(stdout, "-------------------------------------------------------------");

	ec_group group = ec_group_init_set_str_hex(test->name, test->p, test->a, test->b, test->Gx, test->Gy, test->order, "1");

	// Key pair generation test
	mpz_t d;
	mpz_init_set_str(d, test->d, 16);
	ec_point Q = ec_point_init_set_str_hex(test->Qx, test->Qy);
	ec_point G = ec_point_init_set_str_hex(test->Gx, test->Gy);

	// Check the generated public key
	ecs_keygen_test(G, Q, d, group);

	mpz_t order;
	mpz_init_set(order, group->order);

	// Initialize and set up an ec_key
	ec_key eckey = ec_key_init_set(group, Q, d);


	// Signature Generation Test
	mpz_t k, kinv, r, e, s;
	mpz_init_set_str(k, test->k, 16);
	mpz_init_set_str(kinv, test->kinv, 16);
	mpz_init_set_str(r, test->r, 16);
	mpz_init_set_str(e, test->e, 10);
	mpz_init_set_str(s, test->s, 16);
	ec_point R = ec_point_init_set_str_hex(test->Rx, test->Ry);

	fprintf(stdout, "\nVerifying signature generation algorithm ...\n");
	// Given k, test kinv, R and r
	mpz_t X; mpz_init(X);
	if (!mod_invert(X, k, order))
		fprintf(stdout, "Error while computing a modular inverse !\n");

	if (!mpz_cmp(X, kinv))
		fprintf(stdout, "Generate an k inverse: passed !\n");
	else
		fprintf(stdout, "Generate an k inverse:  failed !\n");

	mpz_clear(X);

	ec_point tmp_point = ecp_mul_atomic(G, k, group);
	if (!ec_point_cmp(R, tmp_point, group->field))
		printf("Test signature generation failed -- R = k * G incorrect !\n");
	else
		fprintf(stdout, "Generate: R = k * G passed !\n");


	mpz_t tmp_r; mpz_init(tmp_r);
	mpz_mod(tmp_r, tmp_point->x, order);

	if (mpz_cmp(r, tmp_r) != 0)
		printf("Test signature generation failed -- r (Rx) incorrect !\n");
	else
		fprintf(stdout, "Generate: r (Rx) passed !\n");


	ec_point_free(tmp_point); mpz_clear(tmp_r);

	// Given message, test digest generated
	char *msg, *dgst;
	int length = strlen(test->msg);
	msg = (char*)malloc(sizeof(char) * (length + 1));
	msg[length] = '\0';
	strcpy(msg, test->msg);
	length = strlen(test->dgst);
	dgst = (char*)malloc(sizeof(char) * (length + 1));
	dgst[length] = '\0';
	strcpy(dgst, test->dgst);

	int l = mpz_sizeinbase(order, 2);
	char *hash_dgst = NULL;

	switch (l) {
	case 224 :
		hash_dgst = sha224(msg);
		break;
	case 256 :
		hash_dgst = sha256(msg);
		break;
	case 384 :
		hash_dgst = sha384(msg);
		break;
	default:
		printf("Invalid message length !\n");
	}

	if (strcmp(dgst, hash_dgst) != 0)
		printf("Hash function test: failed !\n");
	else
		fprintf(stdout, "Hash function test: passed !\n");

	//printf("Digest is %s\n", dgst);
	//printf("Digest output is %s\n", hash_dgst);

	/* Convert bit string of hash digest to an integer e */
	mpz_t tmp_e;
	mpz_init_set_str(tmp_e, dgst, 16);
	if (!mpz_cmp(tmp_e, e))
		fprintf(stdout, "Convert hash digest string to an integer: passed \n");
	else
		fprintf(stdout, "Convert hash digest string to an integer: failed \n");

	mpz_clear(tmp_e);

	ecdsa_sig sig = ecdsa_sign(dgst, length, kinv, r, eckey);

	if (sig == NULL)
			fprintf(stdout, "Error occurred during generating signature !\n");
	else if (!mpz_cmp(sig->s, s))
		fprintf(stdout, "Generate signature s: passed !\n");
	else
		fprintf(stdout, "Generate signature s: failed !\n");

	// Signature verification test
	fprintf(stdout, "\nVerifying signature verification algorithm ...\n");
	mpz_t tmp_w, w, tmp_u1, u1, tmp_u2, u2;
	mpz_init_set_str(w, test->w, 16);
	mpz_init_set_str(u1, test->u1, 16);
	mpz_init_set_str(u2, test->u2, 16);
	mpz_init(tmp_w); mpz_init(tmp_u1); mpz_init(tmp_u2);


	if (!mod_invert(tmp_w, sig->s, order))
		fprintf(stdout, "ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_BN_LIB");

	if (!mpz_cmp(tmp_w, w))
		fprintf(stdout, "Compute w: passed !\n");
	else
		fprintf(stdout, "Compute w: failed !\n");
	mpz_clear(tmp_w);

	//u1 = e * w mod order
	mod_mul(tmp_u1, e, w, order);
	if (!mpz_cmp(tmp_u1, u1))
		fprintf(stdout, "Compute u1: passed !\n");
	else
		fprintf(stdout, "Compute u1: failed !\n");
	mpz_clear(tmp_u1);

	//u2 = r * w mod n
	mod_mul(tmp_u2, sig->r, w, order);
	if (!mpz_cmp(tmp_u2, u2))
		fprintf(stdout, "Compute u2: passed !\n");
	else
		fprintf(stdout, "Compute u2: failed !\n");
	mpz_clear(tmp_u2);


		//x = u1*G + u2*Q
	ec_point pt_tmp1 = ecp_mul_atomic(G, u1, group);
	ec_point pt_tmp2 = ecp_mul_atomic(Q, u2, group);
	ec_point tmp_X = ec_point_add_atomic(pt_tmp1, pt_tmp2, group);

	mpz_t x1; mpz_init(x1);
	mpz_mod(x1, tmp_X->x, order);
	//Get the result, by comparing x value with r and verifying that x is NOT at infinity

	if ((mpz_cmp(sig->r, x1) == 0) && !tmp_X->infinity)
		fprintf(stdout, "Signature verification : passed !\n");
	else
		fprintf(stdout, "Signature verification: failed !\n");

	ec_point_free(tmp_X); mpz_clear(x1);

	/* Release memory for struct/variables allocated */
	free(msg); free(dgst); free(hash_dgst);
	mpz_clear(d); mpz_clear(order);
	mpz_clear(w); mpz_clear(u1); mpz_clear(u2);
	mpz_clear(k); mpz_clear(kinv); mpz_clear(r); mpz_clear(e); mpz_clear(s);
	ec_group_free(group); ec_key_free(eckey);
	ec_point_free(G); ec_point_free(Q); ec_point_free(R);
}


int main(int argc, char* argv[]) {

	unsigned i;

	for (i = 0;
			i < sizeof(ecs_params) / sizeof(struct ecdsa_params);
			i++) {
		ecdsa_single_test(&ecs_params[i]);
	}
	return 0;

}



