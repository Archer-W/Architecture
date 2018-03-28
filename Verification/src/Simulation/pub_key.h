/*
 * pub_key.h
 *
 *  Created on: Dec 5, 2017
 *      Author: archer
 */

#ifndef SIMULATION_PUB_KEY_H_
#define SIMULATION_PUB_KEY_H_

#include<string>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include "../Othello/hash.h"
#include "../Othello/othello.h"

#include <iostream>
using namespace std;

/**
 * get the pub_key for each sensor node
 * use the openssl rsa to generate pub keys
 */
string* GeneratePubKey(int KEY_BITS, int KEXP) {
	char * pem_key;
	int keylen;
	RSA * rsa = RSA_generate_key(KEY_BITS, KEXP, NULL, NULL);
	BIO *bio = BIO_new(BIO_s_mem());
	PEM_write_bio_RSAPublicKey(bio, rsa);
	keylen = BIO_pending(bio);
	pem_key = new char[keylen + 1];
	BIO_read(bio, pem_key, keylen);
	//cout << pem_key << endl;
	string *pub_key = new string[1];
	string key = (string) pem_key;
	key.replace(0, 30, "");
	unsigned long key_length = key.length();
	key.replace(key.find("-----END RSA"), key_length, "");
	pub_key[0] = key;
	//BIO_free_all(bio);
	//RSA_free(rsa);
	delete[] pem_key;
	return pub_key;
}

/*
 get the public key and corresponding private key for encrypting and decrypting the certificates of public keys
 */
string* GenerateKey(int KEY_BITS, int KEXP) {
	char *pub_pem_key, *private_pem_key;
	int pub_keylen, private_keylen;
	RSA * rsa = RSA_generate_key(KEY_BITS, KEXP, NULL, NULL);
	BIO *pub_bio = BIO_new(BIO_s_mem());
	BIO *private_bio = BIO_new(BIO_s_mem());
	PEM_write_bio_RSA_PUBKEY(pub_bio, rsa);  //get the generated public key
	PEM_write_bio_RSAPrivateKey(private_bio, rsa, NULL, NULL, 0, NULL, NULL); // get the generated private key
	pub_keylen = BIO_pending(pub_bio);
	pub_pem_key = new char[pub_keylen + 1];
	BIO_read(pub_bio, pub_pem_key, pub_keylen);

	private_keylen = BIO_pending(private_bio);
	private_pem_key = new char[private_keylen + 1];
	BIO_read(private_bio, private_pem_key, private_keylen);
	//cout << pem_key << endl;
	BIO_free_all(pub_bio);
	BIO_free_all(private_bio);
	//RSA_free(rsa);
	string pub_key = pub_pem_key;
	string private_key = private_pem_key;
	string *result_key = new string[2];
	result_key[0] = pub_key;
	result_key[1] = private_key;
	delete[] pub_pem_key;
	delete[] private_pem_key;
	return result_key;
}

/*
 create RSA for encryption and decryption
 */
RSA* CreateRSA(unsigned char * key, int index) {
	RSA *rsa = NULL;
	BIO *keybio;
	keybio = BIO_new_mem_buf(key, -1);
	if (keybio == NULL) {
		cout << "Failed to create key BIO" << endl;
		return 0;
	}
	if (index) {
		rsa = PEM_read_bio_RSA_PUBKEY(keybio, NULL, NULL, NULL);
	} else {
		rsa = PEM_read_bio_RSAPrivateKey(keybio, NULL, NULL, NULL);
	}
	return rsa;
}

/*
 encrypt data with public key
 */
int PublicEncrypt(unsigned char * data, int data_len, unsigned char * key,
		unsigned char *encrypted) {
	RSA * rsa = CreateRSA(key, 1);
	cout << "rsa over" << endl;
	int result = RSA_public_encrypt(data_len, data, encrypted, rsa,
			RSA_PKCS1_PADDING);
	return result;
}

/**
 * use Md5 hash to hash the pub key
 */
string GenerateMd5ForPubKey(string pub_key) {
	unsigned char digest[MD5_DIGEST_LENGTH];
	//cout<<MD5_DIGEST_LENGTH<<endl;
	MD5((unsigned char*) pub_key.c_str(), pub_key.length(),
			(unsigned char*) digest);
	char md5_pub_key[2 * MD5_DIGEST_LENGTH + 1];
	for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
		sprintf(&md5_pub_key[i * 2], "%02x", (unsigned int) digest[i]);
	}
	return md5_pub_key;
}

/*
 use SHA256 to hash the public key
 */
string GenerateSHA256ForPublicKey(string pub_key) {
	unsigned char digest[SHA256_DIGEST_LENGTH];
	//cout<<SHA256_DIGEST_LENGTH<<endl;
	SHA256((unsigned char*) pub_key.c_str(), pub_key.length(),
			(unsigned char*) digest);
	char sha256_pub_key[2 * SHA256_DIGEST_LENGTH + 1];
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
		sprintf(&sha256_pub_key[i * 2], "%02x", (unsigned int) digest[i]);
	return sha256_pub_key;
}

/*
 * use SHA384 to hash the public key
 */
string GenerateSHA384ForPublicKey(string pub_key) {
	unsigned char digest[SHA384_DIGEST_LENGTH];
	SHA256((unsigned char*) pub_key.c_str(), pub_key.length(),
			(unsigned char*) digest);
	char sha384_pub_key[2 * SHA384_DIGEST_LENGTH + 1];
	for (int i = 0; i < SHA384_DIGEST_LENGTH; i++)
		sprintf(&sha384_pub_key[i * 2], "%02x", (unsigned int) digest[i]);
	return sha384_pub_key;
}

/*
 * use SHA512 to hash the public key
 */
string GenerateSHA512ForPublicKey(string pub_key) {
	unsigned char digest[SHA512_DIGEST_LENGTH];
	SHA256((unsigned char*) pub_key.c_str(), pub_key.length(),
			(unsigned char*) digest);
	char sha512_pub_key[2 * SHA512_DIGEST_LENGTH + 1];
	for (int i = 0; i < SHA512_DIGEST_LENGTH; i++)
		sprintf(&sha512_pub_key[i * 2], "%02x", (unsigned int) digest[i]);
	return sha512_pub_key;
}

/*
 generate the public key hash
 */
string GeneratePubKeyHash(string pub_key, int hash_type_) {
	string pub_key_hash = "";
	switch (hash_type_) {
	case 5:
		pub_key_hash = GenerateMd5ForPubKey(pub_key);
		break;
	case 256:
		pub_key_hash = GenerateSHA256ForPublicKey(pub_key);
		break;
	case 384:
		pub_key_hash = GenerateSHA384ForPublicKey(pub_key);
		break;
	case 512:
		pub_key_hash = GenerateSHA512ForPublicKey(pub_key);
		break;
	default:
		cout << "error hash type" << endl;
		break;
	}
	return pub_key_hash;
}

#endif /* SIMULATION_PUB_KEY_H_ */
