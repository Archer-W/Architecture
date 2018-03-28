/*
 * Initialization.h
 *
 *  Created on: Mar 1, 2018
 *      Author: minmei
 */
#include <iostream>
#include <stdlib.h>
#include <time.h>
#include "node.h"
using namespace std;

#ifndef SIMULATION_INITIALIZATION_H_
#define SIMULATION_INITIALIZATION_H_

#define random(x) (rand()%x)

/*
 * initialize the malicious nodes
 */
void GenerateMaliciousNode(int SENSOR_NUMBER_, int MALICIOUS_NODE_NUMBER_, Node<int, unsigned char*> * sensor_nodes_, int* m_nodes) {
	srand((int) time(0));
	int number = 0;
	bool not_full = true;
	while (not_full) {
		int malicious_node = random(SENSOR_NUMBER_);
		while (std::find(m_nodes, m_nodes + MALICIOUS_NODE_NUMBER_,
				malicious_node) != m_nodes + MALICIOUS_NODE_NUMBER_) {
			malicious_node = random(SENSOR_NUMBER_);
		}
		m_nodes[number++] = malicious_node;
		if (number == MALICIOUS_NODE_NUMBER_)
			not_full = false;
	}
	for (int i = 0; i < MALICIOUS_NODE_NUMBER_; i++) {
		sensor_nodes_[m_nodes[i]].SetBadNode();
	}
}

#endif /* SIMULATION_INITIALIZATION_H_ */
