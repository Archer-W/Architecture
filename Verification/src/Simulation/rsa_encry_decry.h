#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include<string>
#include <ctype.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <iostream>
using namespace std;

// I'm not using BIO for base64 encoding/decoding.  It is difficult to use.
// Using superwills' Nibble And A Half instead
// https://github.com/superwills/NibbleAndAHalf/blob/master/NibbleAndAHalf/base64.h
#include "base64.h"

// The PADDING parameter means RSA will pad your data for you
// if it is not exactly the right size
//#define PADDING RSA_PKCS1_OAEP_PADDING
#define PADDING RSA_PKCS1_PADDING
//#define PADDING RSA_NO_PADDING

RSA* loadPUBLICKeyFromString(const char* publicKeyStr) {
	// A BIO is an I/O abstraction (Byte I/O?)
	// BIO_new_mem_buf: Create a read-only bio buf with data
	// in string passed. -1 means string is null terminated,
	// so BIO_new_mem_buf can find the dataLen itself.
	// Since BIO_new_mem_buf will be READ ONLY, it's fine that publicKeyStr is const.
	BIO* bio = BIO_new_mem_buf((void*) publicKeyStr, -1); // -1: assume string is null terminated
	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // NO NL
	RSA* rsaPubKey = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
	// Load the RSA key from the BIO
	//RSA* rsaPubKey = PEM_read_bio_RSA_PUBKEY( bio, NULL, NULL, NULL ) ;
	if (!rsaPubKey)
		printf(
				"ERROR: Could not load PUBLIC KEY!  PEM_read_bio_RSA_PUBKEY FAILED: %s\n",
				ERR_error_string(ERR_get_error(), NULL));

	BIO_free(bio);
	return rsaPubKey;
}

RSA* loadPRIVATEKeyFromString(const char* privateKeyStr) {
	BIO *bio = BIO_new_mem_buf((void*) privateKeyStr, -1);
	//BIO_set_flags( bio, BIO_FLAGS_BASE64_NO_NL ) ; // NO NL
	RSA* rsaPrivKey = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);

	if (!rsaPrivKey)
		printf(
				"ERROR: Could not load PRIVATE KEY!  PEM_read_bio_RSAPrivateKey FAILED: %s\n",
				ERR_error_string(ERR_get_error(), NULL));

	BIO_free(bio);
	return rsaPrivKey;
}

unsigned char* rsaEncrypt(RSA *pubKey, const unsigned char* str, int dataSize,
		int *resultLen) {
	int rsaLen = RSA_size(pubKey);
	unsigned char* ed = (unsigned char*) malloc(rsaLen);

	// RSA_public_encrypt() returns the size of the encrypted data
	// (i.e., RSA_size(rsa)). RSA_private_decrypt()
	// returns the size of the recovered plaintext.
	*resultLen = RSA_private_encrypt(dataSize, (const unsigned char*) str, ed,
			pubKey, PADDING);
	if (*resultLen == -1)
		printf("ERROR: RSA_public_encrypt: %s\n",
				ERR_error_string(ERR_get_error(), NULL));
	return ed;
}

unsigned char* rsaDecrypt(RSA *publicKey, const unsigned char* encryptedData,
		int *resultLen) {
	int rsaLen = RSA_size(publicKey); // That's how many bytes the decrypted data would be
	unsigned char *decryptedBin = (unsigned char*) malloc(rsaLen);
	*resultLen = RSA_public_decrypt(rsaLen, encryptedData,decryptedBin, publicKey, PADDING);

	if (*resultLen == -1)
		printf("ERROR: RSA_private_decrypt: %s\n",
				ERR_error_string(ERR_get_error(), NULL));

	return decryptedBin;
}

// You may need to encrypt several blocks of binary data (each has a maximum size
// limited by pubKey).  You shoudn't try to encrypt more than
// RSA_LEN( pubKey ) bytes into some packet.
// returns base64( rsa encrypt( <<binary data>> ) )
// base64OfRsaEncrypted()
// base64StringOfRSAEncrypted
// rsaEncryptThenBase64
char* rsaEncryptThenBase64(RSA *privKey, unsigned char* binaryData,
		int binaryDataLen, int *outLen) {
	int encryptedDataLen;

	// RSA encryption with public key
	unsigned char* encrypted = rsaEncrypt(privKey, binaryData, binaryDataLen,
			&encryptedDataLen);
	//cout<<"encryptedDatalen "<<encryptedDataLen<<endl;

	// To base 64
	int asciiBase64EncLen;
	char* asciiBase64Enc = base64(encrypted, encryptedDataLen,
			&asciiBase64EncLen);

	// Destroy the encrypted data (we are using the base64 version of it)
	free(encrypted);

	// Return the base64 version of the encrypted data
	return asciiBase64Enc;
}

// rsaDecryptOfUnbase64()
// rsaDecryptBase64String()
// unbase64ThenRSADecrypt()
// rsaDecryptThisBase64()
unsigned char* rsaDecryptThisBase64(RSA *publicKey, char* base64String,
		int *outLen) {
	int encBinLen;
	unsigned char* encBin = unbase64(base64String, (int) strlen(base64String),
			&encBinLen);
	// rsaDecrypt assumes length of encBin based on privKey
	unsigned char *decryptedBin = rsaDecrypt(publicKey, encBin, outLen);
	free(encBin);
	return decryptedBin;
}

/*
 Use private_key to encrypt data
 the returned value needs to be freed by user
 */
char* Encryption(unsigned char* data, string private_key) {
	ERR_load_crypto_strings();

	const char *b64_private_key = private_key.c_str();
	RSA *private_key_rsa = loadPRIVATEKeyFromString(b64_private_key);

	int data_size = (int) strlen((char*) data);
	int length;

	char* encrypted_data = rsaEncryptThenBase64(private_key_rsa, data, data_size,
			&length);
	//unsigned char* encrypted_data = rsaEncrypt(pub_key_rsa,data,data_size,&length);
	RSA_free(private_key_rsa); // free the public key when you are done all your encryption
	char* &result = encrypted_data;
	ERR_free_strings();
	//free(encrypted_data);
	return result;
}

/*
 decrypt the encrypted data with private key, and compare whether the decrypted data is equal to the raw data or not
 */
bool Decryption(char* data, char* encrypted_data, string public_key) {
	//ERR_load_crypto_strings();
	int rBinLen;
	const char* b64_pub_key = public_key.c_str();
	RSA *pub_key_rsa = loadPUBLICKeyFromString(b64_pub_key);
	//unsigned char* rBin=rsaDecrypt(priv_key_rsa, encrypted_data, &rBinLen);
	unsigned char* rBin = rsaDecryptThisBase64(pub_key_rsa, encrypted_data,
			&rBinLen);
	//printf("Decrypted %d bytes, the recovered data is:\n%.*s\n\n", rBinLen, rBinLen, rBin ) ;
	// terminated, so we only print rBinLen chrs
	RSA_free(pub_key_rsa);
	int data_size = (int) strlen((char*) data);
	bool allEq = true;
	for (int i = 0; i < data_size; i++)
		allEq &= (data[i] == rBin[i]);
	bool result = true;
	if (allEq) {
	}
	//puts( "DATA TRANSFERRED INTACT!" ) ;
	else {
		puts("ERROR, recovered binary does not match sent binary");
		result = false;
	}
	//free( str ) ;
	free(rBin);
	ERR_free_strings();
	return result;
}
