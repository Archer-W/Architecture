/*
 * othello_output.cpp
 *
 *  Created on: Feb 28, 2018
 *      Author: minmei
 */
#include "othello_output.h"
#include <string>
#include <iostream>
#include <sstream>
#include <stdint.h>
using namespace std;

/*
 get the CheckSum of certificate
 */
unsigned int GetCheckSum(unsigned char* certificate){
    int char_size = CHECK_SUM_LENGTH / (sizeof(char)*8);
    char* check = new char[char_size];
    for(int i=0;i<char_size;i++)
    	check[i]=certificate[i];
    unsigned int check_num = *reinterpret_cast<unsigned int*>(check);
    return check_num;
}

OthelloOutput GenerateOthelloOutput(unsigned int location,  unsigned int check_sum){
	OthelloOutput othello_output_value;
    othello_output_value.check_sum = check_sum;
    othello_output_value.location_num = location;
	return othello_output_value;
}

char* GetLocationNumber(int key){
		char *buffer = new char[LOCATION_LENGTH];
		for(int i=0;i<LOCATION_LENGTH;i++){
			while(key !=0){
				buffer[i] = key % 2;
				key = key / 2;
				//cout<< typeid(key % 2).name()<<endl;
			}
		}
		return buffer;
}




