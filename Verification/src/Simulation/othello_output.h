/*
 * othello_output.h
 *
 *  Created on: Dec 6, 2017
 *      Author: archer
 */

#ifndef SIMULATION_OTHELLO_OUTPUT_H_
#define SIMULATION_OTHELLO_OUTPUT_H_

#define CHECK_SUM_LENGTH 32
#define LOCATION_LENGTH 16

#include <string>
#include <iostream>
#include <sstream>
#include <stdint.h>
using namespace std;

/**
 * define the format for Othello output for a key
 */
struct OthelloOutput{
    unsigned int check_sum: CHECK_SUM_LENGTH;
	unsigned int location_num: LOCATION_LENGTH;
};

unsigned int GetCheckSum(unsigned char* certificate);
OthelloOutput GenerateOthelloOutput(unsigned int location, unsigned int check_sum);
char* GetLocationNumber(int key);









#endif /* SIMULATION_OTHELLO_OUTPUT_H_ */
