/*
 * ec_key.c
 *
 *  Created on: Oct 14, 2015
 *      Author: tslld
 */

#include "ecdsa.h"
#include "ec.h"
#include "ec_point.h"


ec_group ec_key_get_group(const ec_key key) {
	/* Should not be released after calling. If not ec_key will lost group element */
	return key->group;
}

/** Sets the EC_GROUP of a EC_KEY object.
 *  \param  key    EC_KEY object
 *  \param  group  EC_GROUP to use in the EC_KEY object (note: the EC_KEY
 *                 object will use an own copy of the EC_GROUP).
 *  \return 1 on success and 0 if an error occurred.
 */
int ec_key_set_group(ec_key key, const ec_group group) {

	/* Clear the old group */
	//if (key->group != NULL)
	//	ec_group_free(key->group);

	ec_group_cpy(key->group, group);
	//key->group = ec_group_dup(group);
	return (key->group == NULL) ? 0 : 1;

}

/** Returns the private key of a EC_KEY object.
 *  \param  key  EC_KEY object
 *  \return a BIGNUM with the private key (possibly NULL).
 */
void ec_key_get_private_key(mpz_t ret, const ec_key key){
	mpz_set(ret, key->priv_key);
}

/** Sets the private key of a EC_KEY object.
 *  \param  key  EC_KEY object
 *  \param  prv  BIGNUM with the private key (note: the EC_KEY object
 *               will use an own copy of the BIGNUM).
 *  \return 1 on success and 0 if an error occurred.
 */
void ec_key_set_private_key(ec_key key, const mpz_t prv) {

	mpz_set(key->priv_key, prv);
}

/** Returns the public key of a EC_KEY object.
 *  \param  key  the EC_KEY object
 *  \return a EC_POINT object with the public key (possibly NULL)
 */
ec_point ec_key_get_public_key(const ec_key key){
	/* Should not be released after calling. If not ec_key will lost pub_key element */
	return key->pub_key;
}

/** Sets the public key of a EC_KEY object.
 *  \param  key  EC_KEY object
 *  \param  pub  EC_POINT object with the public key (note: the EC_KEY object
 *               will use an own copy of the EC_POINT object).
 *  \return 1 on success and 0 if an error occurred.
 */
int ec_key_set_public_key(ec_key key, const ec_point pub_key) {
	/* Clear the old public key */
	//if (key->pub_key != NULL)
	//	ec_point_free(key->pub_key);
	ec_point_cpy(key->pub_key, pub_key);
	//key->pub_key = ec_point_dup(pub_key);
	return (key->pub_key == NULL) ? 0 : 1;
}


/** Verifies that a private and/or public key is valid.
 *  \param  key  the EC_KEY object
 *  \return 1 on success and 0 otherwise.
 */
int ec_key_check_key(const ec_key eckey) {

	ec_group group = ec_group_init();

	group = ec_key_get_group(eckey);

	if (!eckey || ! group || !eckey->pub_key) {
		fprintf(stdout, "EC_F_EC_KEY_CHECK_KEY, ERR_R_PASSED_NULL_PARAMETER");
		return 0;
	}

	if (ec_point_is_at_infinity(eckey->pub_key)) {
		fprintf(stdout, "EC_F_EC_KEY_CHECK_KEY, EC_R_POINT_AT_INFINITY");
		return 0;
	}

	/* testing whether the pub_key is on the elliptic curve */
	if (!ec_point_is_on_curve(eckey->pub_key, eckey->group)) {
		fprintf(stdout, "EC_F_EC_KEY_CHECK_KEY, EC_R_POINT_IS_NOT_ON_CURVE");
		return 0;
	}

	/* Test whether the order of the public key is the same the order of group */
	ec_point tmp = ecp_mul_atomic(eckey->pub_key, group->order, group);
	if (!tmp->infinity) {
		fprintf(stdout, "EC_F_EC_KEY_CHECK_KEY, EC_R_POINT_HAS_NOT_ORDER_CURVE");
		return 0;
	}

    return 1;

}

/**	Check the validation of an ECDSA public key
 * 	\param Q	pointer to an ec point structure
 * 	\param ec	pointer to an ec_group structure
 * 	\return 	1 if Q is valid (on ec and order of Q is the order of group);
 * 				0 if fail to any test
 */

int ec_key_check_public_key(ec_point Q, ec_group group) {

	int ok = 0;

	if (!group || !Q) {
		fprintf(stdout, "Public key validation. Point or group provide is NULL !\n");
		return (ok);
	}

	/* Check that Q <> point-at-infinity */
	if (ec_point_is_at_infinity(Q)) {
		fprintf(stdout, "Public key validation. Q is a POINT_AT_INFINITY !\n");
		return (ok);
	}

	/* Check that Q_x, Q_y are properly represented of F_q */

	mpz_t one; mpz_init(one);
	mpz_set_ui(one, 1);
	if(	mpz_cmp(Q->x,one) < 0 && mpz_cmp(group->order, Q->x) <= 0 &&
			mpz_cmp(Q->y, one) < 0 && mpz_cmp(group->order, Q->y) <= 0) {
		fprintf(stdout, "Point Q is not defined in Fp !\n");
		mpz_clear(one);
		return (ok);
	}
	mpz_clear(one);

	/* Check whether Q is on the elliptic curve */
	if (!ec_point_is_on_curve(Q, group)) {
		fprintf(stdout, "Public key validation. Q is NOT_ON_CURVE \n");
		return (ok);
	}

	/** Check whether the order of the public key is the same the order of group
	 * 	That is, order * Q = point_at_infinity
	 */
	ec_point tmp = ecp_mul_atomic(Q, group->order, group);
	if (!tmp->infinity) {
		fprintf(stdout, "Public key validation. Q has NOT_ORDER_CURVE \n");
		ec_point_free(tmp);
		return (ok);
	}

	ec_point_free(tmp);

    ok = 1;

	return (ok);
}


