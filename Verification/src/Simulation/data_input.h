/*
 * data_input.h
 *
 *  Created on: Dec 7, 2017
 *      Author: minmei
 */

#ifndef SIMULATION_DATA_INPUT_H_
#define SIMULATION_DATA_INPUT_H_

#include <string>
using namespace std;

struct DataInputFormat{
	double comp_time;
	double begin_time;
    double real_begin_time;
    double end_time;
    double verify_time;
	int send_node;
	int receiver_node;
    int verify_node;
    int queVeriFini; //0 represents query, 1 represents verify, 2 represents finish
    bool isSigCorr;
    bool isVeriCorr;
};

bool operator< (const DataInputFormat& a, const DataInputFormat& b){
	return a.comp_time > b.comp_time;
}





#endif /* SIMULATION_DATA_INPUT_H_ */
