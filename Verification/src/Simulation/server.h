/*
 * server.h
 *
 *  Created on: Dec 3, 2017
 *      Author: Minmei Wang
 */

#ifndef SIMULATION_SERVER_H_
#define SIMULATION_SERVER_H_
#include <iostream>
#include <fstream>
#include <algorithm>
#include <map>
#include <vector>
#include <list>
#include <math.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <functional>
#include "rsa_sign_verify.h"
#include "othello_output.h"
#include "pub_key.h"
using namespace std;

#define MAXTRUST 100.0
#define eps 1e-8
#define random(x) (rand()%x)

template<class key_type, class certificate_type, class othello_type>
class Server {
private:
	string * pub_key_;
	string * pub_key_hash_;
	unsigned char** pub_key_certificate_;
	int othello_size_;
public:
	Othello<int, unsigned long> global_othello_;
	map<int, int> certificate_store_node_;
	vector<int> othello_vector;
	double ** trust_array;
	map<int, vector<int>> store_nodes;
	int * node_mali_behaviors;
	int sensor_number_;
	double local_time_;
	vector<int> stored_certificate_nodes;

	void SetStoredCertificateNodes(int node_id) {
		stored_certificate_nodes.push_back(node_id);
	}
	struct compare {
		bool operator()(DataInputFormat &a, DataInputFormat &b) {
			return a.verify_time > b.verify_time;
		}
	};

	std::priority_queue<DataInputFormat, vector<DataInputFormat>> event_queue_;

	//set the othello for Server
	void SetGlobalOthello(Othello<int, unsigned long> othello) {
		global_othello_ = othello;
	}

	//update the node of storing the certificates for the sender_node
	//receiver_node can store certificate of sender_node
	bool UpdateStoreNodes(int sender_node, int receiver_node) {
		if (store_nodes.find(sender_node) != store_nodes.end()) {
			vector<int> &ve = store_nodes.find(sender_node)->second;
			//cout<<"update before size "<<store_nodes.find(sender_node)->second.size()<<endl;
			if (find(ve.begin(), ve.end(), receiver_node) == ve.end()) {
				//store_nodes.find(sender_node)->second.push_back(store_node);
				ve.push_back(receiver_node);
				//cout<<"update after size "<<store_nodes.find(sender_node)->second.size()<<endl;
				return true;
			} else
				return false;

		} else {
			vector<int> v;
			v.push_back(receiver_node);
			store_nodes[sender_node] = v;
			return true;
		}
	}

	/**
	 * update the trust value between nodes
	 */
	void UpdateTrust(int initiator, int receiver, bool isGood, ofstream &f) {
		//cout << "initiator " << initiator << " receiver " << receiver << endl;
		if (isGood) {
			double value = trust_array[receiver][initiator] * 2.0;
			double min_value = min(value, MAXTRUST);
			//cout << value << " " << min_value << endl;
			trust_array[receiver][initiator] = min_value;
		} else {
			double value = trust_array[receiver][initiator] / 4.0;
			//double value = 0.0;
			double min_value = min(value, 1.0 / pow(4, 3));
			if (fabs(value - min_value) < eps)
				trust_array[receiver][initiator] = 0.0;
			else
				trust_array[receiver][initiator] = value;
		}
		for (int i = 0; i < sensor_number_; i++) {
			if (i != receiver) {
				if (isGood) {
					double value = 0.7 * trust_array[i][initiator]
							+ 0.3 * trust_array[receiver][initiator];
					double min_value = min(value, MAXTRUST);
					trust_array[i][initiator] = min_value;
				} else {
					double value = 0.7 * trust_array[i][initiator]
							+ 0.3 * trust_array[receiver][initiator];
					double max_value = min(value, MAXTRUST);
					trust_array[i][initiator] = max_value;

				}
			}
		}
		//cout << "print trust value between each node:" << endl;
		PrintAllTrust(f);
	}

	/*
	 * print all trust value between each node
	 */
	void PrintAllTrust(ofstream &f) {
		for (int i = 0; i < sensor_number_; i++)
			PrintTrust(i, f);
		//cout<<endl;
		f << endl;
	}

	/*
	 * print all the sensor number's trust to sensor node_id
	 */
	void PrintTrust(int node_id, ofstream &f) {
		double sum = 0.0;
		for (int i = 0; i < sensor_number_; i++)
			sum += trust_array[i][node_id];
		sum = sum / sensor_number_;
		//cout << sum<<" ";
		f << sum << " ";
	}

	/**
	 * build the Server node
	 * assume the Server node know all the keys and corresponding certificates and locations
	 */
	Server(string *pub_key, string *pub_key_hash,
			unsigned char** pub_key_certificate, int number,
			int sensor_number) {
		pub_key_ = pub_key;
		pub_key_hash_ = pub_key_hash;
		pub_key_certificate_ = pub_key_certificate;
		othello_size_ = number;
		trust_array = new double*[sensor_number];
		//the trust value between each two nodes are the same 1
		for (int i = 0; i < sensor_number; i++) {
			trust_array[i] = new double[sensor_number];
			fill(trust_array[i], (trust_array[i] + sensor_number), 1.0);
		}
		node_mali_behaviors = new int[sensor_number];
		fill(node_mali_behaviors, node_mali_behaviors + sensor_number, 0);
		sensor_number_ = sensor_number;
		local_time_ = 1.0;
	}

	Server() {
		othello_size_ = 0;
		sensor_number_ = 0;
		local_time_ = 1.0;
	}

	int GetOthelloSize() {
		return othello_size_;
	}
	void SetOthelloSize(int number) {
		othello_size_ = number;
	}

	/**
	 * record the bad behaviors about each node
	 */
	void UpdateBadNumbers(int index) {
		node_mali_behaviors[index] += 1;
	}

	/*
	 * update othello according to the trust value and store_nodes
	 */
	void UpdateOthello(bool has_trust) {
		map<int, vector<int>>::iterator it;
		for (it = store_nodes.begin(); it != store_nodes.end(); it++) {
			int sender_node = it->first;
			vector<int> v = it->second;
			//cout<<sender_node<<" "<<v[0]<<endl;
			if (has_trust) {
				int size = v.size();
				double* trust_value = new double[size];
				double sum = 0.0;
				double max_trust = 0.0;
				int index = 0;
				for (int i = 0; i < size; i++) {
					int node_s = v[i];
					trust_value[i] = trust_array[sender_node][node_s];
					if (trust_value[i] > max_trust) {
						max_trust = trust_value[i];
						index = i;
					}
					sum += trust_value[i];
				}
				int verify_node = v[index];
				//cout << trust_value[index] << endl;
				double max_value = max(trust_value[index], 0.0);
				if (fabs(trust_value[index] - max_value) < eps) {
					unsigned long othello_value = global_othello_.query(
							sender_node);
					OthelloOutput output_value =
							*reinterpret_cast<OthelloOutput*>(&othello_value);
					output_value.location_num = verify_node;
					unsigned long updated_output_value =
							*reinterpret_cast<unsigned long*>(&output_value);
					global_othello_.updateKeyValue(sender_node,
							updated_output_value);
					global_othello_.updateValue(sender_node);
				}
			} else {
				//cout<<"update begin"<<endl;
				int rand_num = random(v.size());
				int verify_node = v[rand_num];
				unsigned long othello_value = global_othello_.query(
						sender_node);
				OthelloOutput output_value =
						*reinterpret_cast<OthelloOutput*>(&othello_value);
				output_value.location_num = verify_node;
				unsigned long updated_output_value =
						*reinterpret_cast<unsigned long*>(&output_value);
				global_othello_.updateKeyValue(sender_node,
						updated_output_value);
				global_othello_.updateValue(sender_node);
				//cout<<"update over"<<endl;

			}
			//else{
			//cout<<max_value<<"don't update"<<endl;
			//}
		}
	}

	/**
	 * scheduing event
	 */
	void ScheduleEvent(DataInputFormat &event, string * pub_key_,
			string * pub_key_hash_, unsigned char** pub_key_certificate_,
			int sensor_numbers, double begin_time, string &rsa_pub_key,
			int hash_type, int out_len) {
		int type = event.queVeriFini;
		int sender_node = event.send_node;
		if (type == 1) {
			//do verification
			unsigned long verify_start_s = clock();
			GeneratePubKeyHash(pub_key_[sender_node], hash_type);
			int verify_result = VerifyCertificate(pub_key_hash_[sender_node],
					pub_key_certificate_[sender_node], rsa_pub_key, hash_type,
					out_len);
			if (verify_result != 1)
				cout << "wrong certificate, error!" << endl;
			unsigned long verify_stop_s = clock();
			double verify_time_interval = (verify_stop_s - verify_start_s)
					/ double(CLOCKS_PER_SEC) * 1000;
			double time = begin_time + verify_time_interval;
			local_time_ = time;
			event.end_time = time;
			event.queVeriFini = 2;  //this event is finished
		} else {
			cout << "server error" << endl;
			exit(-1);
		}
	}

	/**
	 * get the certificate of key
	 */
	unsigned char* GetCertificate(key_type key) {
		return pub_key_certificate_[key];
	}

	int VerifyCertificate(string pub_key_hash, unsigned char* certificate,
			string rsa_pub_key, int hash_type, unsigned int out_len) {
		return VerifyData(hash_type, pub_key_hash, certificate, rsa_pub_key,
				out_len);
	}

	void DeleteVerifyNode(int sender_node, int verify_node) {
		int verify_node_get = certificate_store_node_.find(sender_node)->second;
		if (verify_node == verify_node_get) {
			certificate_store_node_.erase(sender_node);
		} else {
			cout << "update othello data due to malicious code error" << endl;
		}
	}

};

#endif /* SIMULATION_SERVER_H_ */
