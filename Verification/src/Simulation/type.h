/*
 * type.h
 *
 *  Created on: Dec 4, 2017
 *      Author: Minmei Wang
 */

#ifndef SIMULATION_TYPE_H_
#define SIMULATION_TYPE_H_

#include <typeinfo>
using namespace std;

class DefinedType {
private:
	int location_length_;
public:
	/**
	 * define the length of the location output
	 */
	DefinedType(int length){
		location_length_ = length;
	}

	char* GetLocationNumber(int key){
		char *buffer = new char[location_length_];
		for(int i=0;i<location_length_;i++){
			while(key !=0){
				buffer[i] = key % 2;
				key = key / 2;
				//cout<< typeid(key % 2).name()<<endl;
			}
		}
		return buffer;
	}

};

#endif /* SIMULATION_TYPE_H_ */
