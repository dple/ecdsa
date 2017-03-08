/*
 * eck_inits.c
 *
 *  Created on: Nov 20, 2015
 *      Author: tslld
 */

#include "ecdsa.h"
#include "ec.h"
#include "ec_point.h"


/** Creates a new EC_KEY object.
 *  \return EC_KEY object or NULL if an error occurred.
 */
ec_key ec_key_init(void) {
	ec_key key;
	key = malloc(sizeof(struct ec_key_st));
	assert(key != NULL);

	key->group = ec_group_init();
	key->pub_key = ec_point_init();
	mpz_init(key->priv_key);

	return key;
}

ec_key ec_key_init_set(const ec_group group, const ec_point pubkey, const mpz_t privkey) {
	ec_key key;
	key = malloc(sizeof(struct ec_key_st));
	assert(key != NULL);

	key->group = ec_group_dup(group);
	key->pub_key = ec_point_dup(pubkey);
	mpz_init_set(key->priv_key, privkey);

	return key;
}


/** Creates a new EC_KEY object using a named curve as underlying
 *  EC_GROUP object.
 *  \param  name 	the string named of curve.
 *  \return EC_KEY object or NULL if an error occurred.
 */
ec_key ec_key_init_by_curve_name(const char *name) {
	ec_key key;
	key = malloc(sizeof(struct ec_key_st));
	assert(key != NULL);

	key->group = ec_group_init_by_curve_name(name);
    if (key->group == NULL) {
        ec_key_free(key);
        return NULL;
    }
    mpz_init(key->priv_key);
    key->pub_key = ec_point_init();

    return key;
}
