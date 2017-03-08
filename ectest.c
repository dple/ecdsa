/*
 * ectest.c
 *
 *  Created on: Oct 14, 2015
 *      Author: tslld
 */

#include "ecdsa.h"
#include "ec.h"
#include "ec_point.h"

struct nistp_params {
	const char* name;
	const char *p, *a, *b, *Qx, *Qy, *Gx, *Gy, *order, *d;
	const char *Px, *Py, *Tx, *Ty, *Rx, *Ry, *Sx, *Sy, *Dx, *Dy, *x, *y, *Xx, *Xy, *Yx, *Yy;
};

/*
 * NIST test vectors for elliptic curves
 * https://www.nsa.gov/ia/_files/nist-routines.pdf
 *
 */
static const struct nistp_params nistps_params[] = {
	{
	 /* NIST P-224 */
     "secp224r1",
     /* p */
     "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001",
     /* a */
     "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE",
     /* b */
     "B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4",
     /* Qx */
     "E84FB0B8E7000CB657D7973CF6B42ED78B301674276DF744AF130B3E",
     /* Qy */
     "4376675C6FC5612C21A0FF2D2A89D2987DF7A2BC52183B5982298555",
     /* Gx */
     "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21",
     /* Gy */
     "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34",
     /* order */
     "FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D",
     /* d */
     "3F0C488E987C80BE0FEE521F8D90BE6034EC69AE11CA72AA777481E8",
	 /* Px */
	 "6eca814ba59a930843dc814edd6c97da95518df3c6fdf16e9a10bb5b",
	 /* Py */
	 "ef4b497f0963bc8b6aec0ca0f259b89cd80994147e05dc6b64d7bf22",
	 /* Tx */
	 "b72b25aea5cb03fb88d7e842002969648e6ef23c5d39ac903826bd6d",
	 /* Ty */
	 "c42a8a4d34984f0b71b5b4091af7dceb33ea729c1a2dc8b434f10c34",
	 /* Rx, R = P + T */
	 "236f26d9e84c2f7d776b107bd478ee0a6d2bcfcaa2162afae8d2fd15",
	 /* Ry */
	 "e53cc0a7904ce6c3746f6a97471297a0b7d5cdf8d536ae25bb0fda70",
	 /* Sx, S = P - T */
	 "db4112bcc8f34d4f0b36047bca1054f3615413852a7931335210b332",
	 /* Sy */
	 "90c6e8304da4813878c1540b2396f411facf787a520a0ffb55a8d961",
	 /* Dx, D = P + P */
	 "a9c96f2117dee0f27ca56850ebb46efad8ee26852f165e29cb5cdfc7",
	 /* Dy */
	 "adf18c84cf77ced4d76d4930417d9579207840bf49bfbf5837dfdd7d",
	 /* x */
	 "a78ccc30eaca0fcc8e36b2dd6fbb03df06d37f52711e6363aaf1d73b",
	 /* y */
	 "54d549ffc08c96592519d73e71e8e0703fc8177fa88aa77a6ed35736",
	 /* X_x, X = x * P */
	 "96a7625e92a8d72bff1113abdb95777e736a14c6fdaacc392702bca4",
	 /* X_y */
	 "0f8e5702942a3c5e13cd2fd5801915258b43dfadc70d15dbada3ed10",
	 /* Y_x, Y = x * P + y * T */
	 "dbfe2958c7b2cda1302a67ea3ffd94c918c5b350ab838d52e288c83e",
	 /* Y_y */
	 "2f521b83ac3b0549ff4895abcc7f0c5a861aacb87acbc5b8147bb18b",
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
     /* Qx, Q = d * G */
     "b7e08afdfe94bad3f1dc8c734798ba1c62b3a0ad1e9ea2a38201cd0889bc7a19",
     /* Qy */
     "3603f747959dbf7a4bb226e41928729063adc7ae43529e61b563bbc606cc5e09",
     /* Gx */
	 "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
     /* Gy */
	 "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
     /* order */
	 "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
     /* d */
     "c477f9f65c22cce20657faa5b2d1d8122336f851a508a1ed04e479c34985bf96",
	 /* Px */
	 "de2444bebc8d36e682edd27e0f271508617519b3221a8fa0b77cab3989da97c9",
	 /* Py */
	 "c093ae7ff36e5380fc01a5aad1e66659702de80f53cec576b6350b243042a256",
	 /* Tx */
	 "55a8b00f8da1d44e62f6b3b25316212e39540dc861c89575bb8cf92e35e0986b",
	 /* Ty */
	 "5421c3209c2d6c704835d82ac4c3dd90f61a8a52598b9e7ab656e9d8c8b24316",
	 /* Rx, R = P + T */
	 "72b13dd4354b6b81745195e98cc5ba6970349191ac476bd4553cf35a545a067e",
	 /* Ry */
	 "8d585cbb2e1327d75241a8a122d7620dc33b13315aa5c9d46d013011744ac264",
	 /* Sx, S = P - T */
	 "c09ce680b251bb1d2aad1dbf6129deab837419f8f1c73ea13e7dc64ad6be6021",
	 /* Sy */
	 "1a815bf700bd88336b2f9bad4edab1723414a022fdf6c3f4ce30675fb1975ef3",
	 /* Dx, D = P + P */
	 "7669e6901606ee3ba1a8eef1e0024c33df6c22f3b17481b82a860ffcdb6127b0",
	 /* Dy */
	 "fa878162187a54f6c39f6ee0072f33de389ef3eecd03023de10ca2c1db61d0c7",
	 /* x */
	 "c51e4753afdec1e6b6c6a5b992f43f8dd0c7a8933072708b6522468b2ffb06fd",
	 /* y */
	 "d37f628ece72a462f0145cbefe3f0b355ee8332d37acdd83a358016aea029db7",
	 /* X_x, X = x * P */
	 "51d08d5f2d4278882946d88d83c97d11e62becc3cfc18bedacc89ba34eeca03f",
	 /* X_y */
	 "75ee68eb8bf626aa5b673ab51f6e744e06f8fcf8a6c0cf3035beca956a7b41d5",
	 /* Y_x, Y = x * P + y * T */
	 "d867b4679221009234939221b8046245efcf58413daacbeff857b8588341f6b8",
	 /* Y_y */
	 "f2504055c03cede12d22720dad69c745106b6607ec7e50dd35d54bd80f615275",
     },

};

/* test multiplication with group order, long and negative scalars */
static void group_order_tests(ec_group ec) {

	fprintf(stdout, "\nverifying group order ... \n");

	ec_point Rop = ecp_mul_atomic(ec->generator, ec->order, ec);

	if (ec_point_is_at_infinity(Rop))
		fprintf(stdout, "passed ! \n");
	else
		fprintf(stdout, "failed ! \n");


}

static void is_on_curve_test(ec_point P, ec_group ec) {
	fprintf(stdout, "\nverifying whether a point on curve ... \n");

	if (ec_point_is_on_curve(P, ec))
		fprintf(stdout, "passed ! \n");
	else
		fprintf(stdout, "failed ! \n");

}


/* Verify whether R = P + T */
static void ec_add_test(ec_point P, ec_point T, ec_point R, ec_group ec) {
	fprintf(stdout, "\nverifying group addition ... \n");

	//ec_point Rop = ec_point_add_atomic(P, T, ec);
	ec_point Rop = ec_point_add(P, T, ec);

	if (ec_point_cmp(Rop, R, ec->field))
		fprintf(stdout, "passed ! \n");
	else
		fprintf(stdout, "failed ! \n");

	ec_point_free(Rop);
}

/* Verify whether R = P - T */
static void ec_sub_test(ec_point P, ec_point T, ec_point R, ec_group ec) {
	fprintf(stdout, "\nverifying group subtraction ...\n");

	ec_point tmp = ec_point_inverse(T, ec->field);

	ec_point Rop = ec_point_add(P, tmp, ec);
	//ec_point Rop = ec_point_add_atomic(P, tmp, ec);

	if (ec_point_cmp(Rop, R, ec->field))
		fprintf(stdout, "passed ! \n");
	else
		fprintf(stdout, "failed ! \n");

	ec_point_free(tmp);
	ec_point_free(Rop);

}

static void ec_dbl_test(ec_point P, ec_point R, ec_group ec) {
	fprintf(stdout, "\nverifying group doubling operation ...\n");

	//ec_point Rop = ec_point_add_atomic(P, P, ec);
	ec_point Rop = ec_point_dbl(P, ec);

	if (ec_point_cmp(Rop, R, ec->field))
		fprintf(stdout, "passed ! \n");
	else
		fprintf(stdout, "failed ! \n");

	ec_point_free(Rop);

}

static void ecp_mul_test(ec_point G, ec_point Q, mpz_t d, ec_group ec) {
	fprintf(stdout, "\nverifying scalar multiplication ...\n");

	//ec_point Rop = ecp_mul_atomic(G, d, ec);
	ec_point Rop = ecp_mul_rand_montgomery(G, d, ec);
	//ec_point Rop = ecp_mul_montgomery(G, d, ec);

	if (ec_point_cmp(Rop, Q, ec->field))
		fprintf(stdout, "passed ! \n");
	else
		fprintf(stdout, "failed ! \n");

	ec_point_free(Rop);

}

static void ec_dbl_mul_test(ec_point X, ec_point P, ec_point T, mpz_t d, mpz_t e, ec_group ec) {
	fprintf(stdout, "\nverifying double scalar multiplication ...\n");
	ec_point tmp1 = ecp_mul_atomic(P, d, ec);

	ec_point tmp2 = ecp_mul_atomic(T, e, ec);

	ec_point Rop = ec_point_add_atomic(tmp1, tmp2, ec);

	if (ec_point_cmp(Rop, X, ec->field))
		fprintf(stdout, "passed ! \n");
	else
		fprintf(stdout, "failed ! \n");

	ec_point_free(tmp1); ec_point_free(tmp2); ec_point_free(Rop);

}


static void nist_single_test(const struct nistp_params *test) {
	fprintf(stdout, "\n-------------------------------------------------------------");
	fprintf(stdout, "\nVerifying the curve %s. ", test->name);
	fprintf(stdout,
			"This curve is defined by Weierstrass equation\n     y^2 = x^3 + a*x + b  (mod 0x");
	fprintf(stdout, "%s)\n\t a = 0x%s\n\t b = 0x%s\n", test->p, test->a, test->b);

	fprintf(stdout, "-------------------------------------------------------------");

	mpz_t d, x, y;
	mpz_init_set_str(d, test->d, 16);
	mpz_init_set_str(x, test->x, 16);
	mpz_init_set_str(y, test->y, 16);

	ec_group ec = ec_group_init_set_str_hex(test->name, test->p, test->a, test->b, test->Gx, test->Gy, test->order, "1");

	ec_point G = ec_point_init_set_str_hex(test->Gx, test->Gy);
	ec_point Q = ec_point_init_set_str_hex(test->Qx, test->Qy);
	ec_point P = ec_point_init_set_str_hex(test->Px, test->Py);
	ec_point T = ec_point_init_set_str_hex(test->Tx, test->Ty);
	ec_point R = ec_point_init_set_str_hex(test->Rx, test->Ry);
	ec_point S = ec_point_init_set_str_hex(test->Sx, test->Sy);
	ec_point D = ec_point_init_set_str_hex(test->Dx, test->Dy);
	ec_point X = ec_point_init_set_str_hex(test->Xx, test->Xy);
	ec_point Y = ec_point_init_set_str_hex(test->Yx, test->Yy);

	group_order_tests(ec);
	is_on_curve_test(Q, ec);

	ec_add_test(P, T, R, ec);
	ec_sub_test(P, T, S, ec);

	ec_dbl_test(P, D, ec);
	//ec_mul_test(G, Q, d, ec);
	ecp_mul_test(P, X, x, ec);
	ec_dbl_mul_test(Y, P, T, x, y, ec);

	/* Release memory for struct/variables used */
	ec_group_free(ec);
	mpz_clear(d);
	ec_point_free(G);
	ec_point_free(Q);
	ec_point_free(P);
	ec_point_free(T);
	ec_point_free(R);
	ec_point_free(S);
	ec_point_free(D);
}


int main(int argc, char* argv[]) {

	unsigned i;

	for (i = 0;
			i < sizeof(nistps_params) / sizeof(struct nistp_params);
			i++) {
		nist_single_test(&nistps_params[i]);
	}
	return 0;

}

