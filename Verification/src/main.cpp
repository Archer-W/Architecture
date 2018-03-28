/*
 * simulation_test.cpp
 *
 *  Created on: Dec 3, 2017
 *      Author: Minmei Wang
 */
#include<iostream>
#include<string>
#include<list>
#include<map>
#include<iterator>
#include <math.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <queue>
#include <vector>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/md5.h>

#include "./Simulation/node.h"
#include "./Simulation/server.h"
#include "./Simulation/type.h"
#include "./Simulation/pub_key.h"
#include "./Simulation/data_input.h"
#include "./Simulation/probability.h"
#include "./Simulation/event_interval.h"
#include "./Simulation/simulation.h"

using namespace std;

#define SENSOR_NUMBER  200
#define OTHELLO_OUTPUT_NUMBER 7
#define MAX_CLOCK 5000
#define KEY_BITS 2048
#define KEXP 3
#define POISSON_MEAN 10
#define DIGEST_LENGTH 32
#define MALICIOUS_NODE_NUMBER 20
#define random(x) (rand()%x)

int main() {
//	cout << "generate rsa public key & private key for sign and verify:"
//                        			<< endl;
	string *result_key = GenerateKey(KEY_BITS, KEXP);
	Simulation *simulation_test = new Simulation(SENSOR_NUMBER, MAX_CLOCK,
			POISSON_MEAN, MALICIOUS_NODE_NUMBER, KEY_BITS, 256,
			"random_distribution", result_key[0], result_key[1]);
	//test the performance of encryption and decryption
	//simulation_test->TestSignVerifyTime(256,result_key[1],result_key[0],500,"sign-100-5-1024-256.txt","verify-100-5-1024-256.txt");

	//test othello
	//simulation_test->TestOtello();
	//generate the input of the simulation
	simulation_test->GenerateInput();
	cout<<"fast verification simulation result: "<<endl;
	simulation_test->FastVerificationSimulation("f_trust_200_10_20.txt","bad_num_200_10_20.txt","trust_value_200_10_20.txt",true);
	simulation_test->AnalyzeTime("f_trust_200_10_20.txt");
	//simulation_test->AnalyzeTrust("trust10.txt");
//	cout << endl << "verification simulation result " << endl;
	//simulation_test->VerificationSimulation("nontrust_200_10_5000.txt");
	//cout<<endl;

	return 0;

}

