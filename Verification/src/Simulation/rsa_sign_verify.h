/*
 * rsa_sign_verify.h
 *
 *  Created on: Jan 10, 2018
 *      Author: minmei
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include<string>
#include <ctype.h>
#include <iostream>
#include "rsa_encry_decry.h"
using namespace std;

/*
 * sign the data with specific hash and the private key
 */
int SignData(int type, unsigned char* data, string private_key, unsigned char * signed_data, unsigned int &out_len){
    const char *b64_private_key = private_key.c_str();
    RSA *priv_key_rsa = loadPRIVATEKeyFromString(b64_private_key);
    int len = strlen((const char*)data);
	switch(type){
	case 256:
		if(RSA_sign(NID_sha256, data,len,signed_data,&out_len,priv_key_rsa)!=1){
			  cout<<"wrong sign"<<endl;
		}
		break;
	case 1:
		if(RSA_sign(NID_sha1,data,len,signed_data,&out_len,priv_key_rsa)!=1){
					  cout<<"wrong sign"<<endl;
				}
		break;
	case 5:
		if(RSA_sign(NID_md5,data,len,signed_data,&out_len,priv_key_rsa)!=1){
					  cout<<"wrong sign"<<endl;}
		break;
	case 384:
		if(RSA_sign(NID_sha384,data,len,signed_data,&out_len,priv_key_rsa)!=1){
							  cout<<"wrong sign"<<endl;}
		break;
	case 512:
		if(RSA_sign(NID_sha512,data,len,signed_data,&out_len,priv_key_rsa)!=1){
							  cout<<"wrong sign"<<endl;}
		break;
	default:
		break;
	}
	return 0;
}

/*
 * verify data with specific hash and the public key
 */
int VerifyData(int type, string data, unsigned char* sig, string public_key, unsigned int out_len){
	const char *b64_public_key = public_key.c_str();
	int verify_result = 0;
	RSA *public_key_rsa = loadPUBLICKeyFromString(b64_public_key);
	switch(type){
	case 256:
		verify_result = RSA_verify(NID_sha256,(unsigned char*)data.c_str(), data.length(), sig,out_len,public_key_rsa);
		break;
	case 1:
		verify_result = RSA_verify(NID_sha1,(unsigned char*)data.c_str(), data.length(), sig,out_len,public_key_rsa);
		break;
	case 5:
		verify_result = RSA_verify(NID_md5,(unsigned char*)data.c_str(), data.length(), sig,out_len,public_key_rsa);
		break;
	case 384:
		verify_result = RSA_verify(NID_sha384,(unsigned char*)data.c_str(), data.length(), sig,out_len,public_key_rsa);
		break;
	case 512:
		verify_result = RSA_verify(NID_sha512,(unsigned char*)data.c_str(), data.length(), sig,out_len,public_key_rsa);
		break;
	default:
		break;
	}
    if(verify_result != 1)
    {
    	cout<<"verify error "<<endl;
    }
	return verify_result;
}

