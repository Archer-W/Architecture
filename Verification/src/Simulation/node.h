/*
 * node.h
 *
 *  Created on: Dec 3, 2017
 *      Author: Minmei Wang
 */

#ifndef SIMULATION_NODE_H_
#define SIMULATION_NODE_H_

#include <iostream>
#include <list>
#include <map>
#include <queue>
#include <time.h>

#include "../Othello/othello.h"
#include "data_input.h"
using namespace std;

#define random(x) (rand()%x)

#define MAX_CERTIFICATES 15

template<class keyType, class valueType>
class Othello;

template<class key_type, class certificate_type>
class Node {
private:
	int location_;      // record the location of sensor node in the network
	int task_sum_;
	int verify_sum_;
	double busy_interval_;
	int certificates_sum_;
	bool is_good_;

public:
	Othello<int, unsigned long> global_othello_; // record the global Othello in the node
	map<key_type, certificate_type> key_certificates_; //record the certificates list of keys in the node
	priority_queue<DataInputFormat, vector<DataInputFormat>> event_queue_; //a priority queue to store the events to be done
	double local_time_;
	vector<int> bad_node;

	Node() {
		task_sum_ = 0;
		verify_sum_ = 0;
		busy_interval_ = 0.0;
		certificates_sum_ = 0;
		is_good_ = true;
		location_ = 0;
		local_time_ = 0.0;
	}

	/**
	 * scheduing event
	 */
	void ScheduleEvent(DataInputFormat &event, string * pub_key_,
			string * pub_key_hash_, unsigned char** pub_key_certificate_,
			int sensor_numbers, double begin_time, int * m_nodes, int mali_num,
			bool has_trust) {
		int type = event.queVeriFini;
		int sender_node = event.send_node;
		if (type == 0) {
			//do query
			unsigned long query_start_s = clock();
			unsigned long query_result = global_othello_.query(sender_node);
			string public_key = pub_key_[sender_node];
			string public_key_hash = pub_key_hash_[sender_node];
			unsigned char* public_key_certificate =
					pub_key_certificate_[sender_node];

			unsigned int check_sum = GetCheckSum(public_key_certificate);
			OthelloOutput result_to_othello_output =
					*reinterpret_cast<OthelloOutput*>(&query_result); //get node to help verify the public key
			unsigned int othello_check_sum = result_to_othello_output.check_sum;
			//cout<<"query_result: "<<check_sum<<" "<<othello_check_sum<<endl;
			int verify_node = (int) result_to_othello_output.location_num;
			//cout<<"check_sum: "<<check_sum<<" "<<othello_check_sum<<"   verify_node: "<<verify_node<<endl;
			unsigned long query_stop_s = clock();
			double query_time_interval = (query_stop_s - query_start_s)
					/ double(CLOCKS_PER_SEC) * 1000;
			event.queVeriFini = 1;
			if (check_sum == othello_check_sum) {
				//check_sum pass
				double t = begin_time + query_time_interval;
				event.verify_time = t;
				event.comp_time = t;
				local_time_ = t;
				event.verify_node = verify_node;
			} else {
				event.isSigCorr = false;
			}
			//cout<<event.queVeriFini<<" "<<event.verify_node<<endl;

		} else {
			//do verification
			if (has_trust) {
				if (find(m_nodes, m_nodes + mali_num, event.verify_node)
						!= m_nodes + mali_num) {
					//int isbad = random(2);
					int isbad = 1;
					if (isbad == 1) {
						event.isVeriCorr = false;
					}
					bad_node.push_back(event.verify_node);
				}
			}
			unsigned char* real_certificate = GetCertificate(sender_node);
			unsigned long verify_start_s = clock();
			int l = strlen((char*) real_certificate);
			unsigned char* pub_key_certificate =
					pub_key_certificate_[sender_node];
			//cout << "length " << l << endl;
			int result =
					(memcmp(pub_key_certificate, real_certificate, l)) ? 1 : 0;
			if (result != 0)
				cout << endl << "wrong certificate, error!" << endl;
			unsigned long verify_stop_s = clock();
			double verify_time_interval = (verify_stop_s - verify_start_s)
					/ double(CLOCKS_PER_SEC) * 1000;
			double t = begin_time + verify_time_interval;
			local_time_ = t;
			event.end_time = t;
			event.queVeriFini = 2;  //this event is finished
			//cout<<"help verification"<<endl;

		}
	}

	void SetGlobalOthello(Othello<int, unsigned long> othello) {
		global_othello_ = othello;
	}

	// Set and Get the attribute of the node
	void SetBadNode() {
		is_good_ = false;
	}

	bool GetNodeAttri() {
		return is_good_;
	}

	void DeleteKey(key_type key) {
		key_certificates_.erase(key);
		certificates_sum_ -= 1;
	}

	void DeleteCertificates() {
		certificates_sum_ = 0;
		key_certificates_.empty();
	}

	certificate_type GetCertificate(key_type key) {
		return key_certificates_[key];
	}

	void SetBusyInterval(double t) {
		busy_interval_ = t;
	}

	void SetCertificatesSum(int sum) {
		certificates_sum_ = sum;
	}

	double GetBusyInterval() {
		return busy_interval_;
	}
	void SetLocation(int location) {
		location_ = location;
	}
	void SetTaskSum(int sum) {
		task_sum_ = sum;
	}

	int GetTaskSum() {
		return task_sum_;
	}

	void SetVerifySum(int sum) {
		verify_sum_ = sum;
	}

	int GetVerifySum() {
		return verify_sum_;
	}

	int GetCertificatesSum() {
		return certificates_sum_;
	}

	/**
	 * briefly construct a sensor node in the system
	 * @location: record the location of the sensor node
	 */

	/**
	 * save the key and corresponding certificates in this node
	 */
	bool SaveCertificates(key_type key, certificate_type cert) {
		if (certificates_sum_ + 1 <= MAX_CERTIFICATES) {
			key_certificates_[key] = cert;
			++certificates_sum_;
			return true;
		} else
			return false;
	}

	/**
	 * verify the correctness of the certificate of the key
	 * @ key
	 * @ cert
	 */
	bool VerifyCertificate(key_type key, certificate_type cert) {
		if (key_certificates_.find(key) == cert) {
			return true;
		} else {
			return false;
		}
	}

	/**
	 * get othello table from the server
	 */
	void GetGloablOthello(Othello<int, int> othello) {
		global_othello_ = othello;
	}

	/**
	 * to check the certificate of node
	 */
	void CheckCertificate(int node_number, certificate_type cert) {
		int check_result = global_othello_.query(node_number);
		OthelloOutput othello_check_result =
				reinterpret_cast<OthelloOutput&>(check_result);
		if (othello_check_result.check_sum) {
			int help_node = othello_check_result.location_num; //ask for help_node to verify the certificate
		} else {
			cout << "the certificate of the node is wrong" << endl;
		}

	}
};

#endif /* SIMULATION_NODE_H_ */
