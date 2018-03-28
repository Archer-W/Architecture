/*
 * define system simulation for the test
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
#include <stdint.h>
#include <inttypes.h>
#include<sys/timeb.h>
#include<ctime>
#include<fstream>
#include<iterator>
#include<algorithm>
#include<iomanip>
#include<stdio.h>
#include<float.h>
using std::ofstream;

#include "node.h"
#include "server.h"
#include "type.h"
#include "pub_key.h"
#include "data_input.h"
#include "../Othello/othello.h"
#include "othello_output.h"
#include "initialization.h"

using namespace std;

#define OTHELLO_OUTPUT_NUMBER 7
#define KEXP 3
#define random(x) (rand()%x)
#define eps 1e-8
#define UPDATE_INTERVAL 10

class Simulation {
private:
	int* time_sum_;
	int* event_time_;
	int event_sum_;
	int SENSOR_NUMBER_;
	int MAX_CLOCK_;
	int POISSON_MEAN_;
	int MALICIOUS_NODE_NUMBER_;
	int KEY_BITS_;
	int hash_type_;
	string rsa_pub_key_;
	string rsa_private_key_;
	string distribution_type_;
	DataInputFormat * input_data_;
	Para query_para_;
	Para verify_para_;
	Server<int, string, OthelloOutput> server_node_;
	Node<int, unsigned char*> * sensor_nodes_;
	string * pub_key_;
	string * pub_key_hash_;
	unsigned char** pub_key_certificate_;
	map<int, double> idle_from_time_; //set the idle time of any node in the system
	int update_time_;
	unsigned int out_len;
	int* m_nodes;
	int bad_num;
	int bad_chosen_node;
	Hasher32<string> h;
	uint32_t* ha;
	uint32_t * hb;
	uint32_t * certs;
public:
	template<class T>
	int GetArrayLen(T &array) {
		return sizeof(array) / sizeof(array[0]);
	}

	Simulation(int sensor_number, int max_clock, int poisson_mean,
			int malicious_node_number, int key_bits, int hash_type,
			string distribution_type, string rsa_pub_key,
			string rsa_private_key) {
		SENSOR_NUMBER_ = sensor_number;
		MAX_CLOCK_ = max_clock;
		time_sum_ = new int[MAX_CLOCK_ + 1];
		event_time_ = new int[MAX_CLOCK_];
		POISSON_MEAN_ = poisson_mean;
		MALICIOUS_NODE_NUMBER_ = malicious_node_number;
		KEY_BITS_ = key_bits;
		hash_type_ = hash_type;
		distribution_type_ = distribution_type;
		rsa_pub_key_ = rsa_pub_key;
		rsa_private_key_ = rsa_private_key;
		event_sum_ = 0;
		pub_key_ = new string[SENSOR_NUMBER_];
		pub_key_hash_ = new string[SENSOR_NUMBER_];
		pub_key_certificate_ = new unsigned char*[SENSOR_NUMBER_];
		sensor_nodes_ = new Node<int, unsigned char*> [SENSOR_NUMBER_];
		m_nodes = new int[MALICIOUS_NODE_NUMBER_];
		update_time_ = 1;
		idle_from_time_[SENSOR_NUMBER_] = 0.0;
		out_len = 0;
		ha = new u_int32_t[SENSOR_NUMBER_];
		hb = new u_int32_t[SENSOR_NUMBER_];
		certs = new u_int32_t[SENSOR_NUMBER_];
		//server_node_ = new Server<int, string, OthelloOutput>();
		bad_num = 0;
		bad_chosen_node = 0;
	}

	uint32_t GenerateHash(string pub_key, int index, int n) {
		uint32_t key_hash;
		key_hash = h(pub_key);
		int cert_n = 32 - 2 * n;
		unsigned mask;
		//the first n bits is ret1
		mask = ((1 << n) - 1) << (32 - n);
		uint32_t ret1 = (key_hash & mask) >> (32 - n);
		//the middle cert_n bits is ret2
		mask = ((1 << n) - 1) << (cert_n);
		uint32_t ret2 = (key_hash & mask) >> (cert_n);
		//the last cert_n bits is certificate
		mask = (1 << cert_n) - 1;
		uint32_t certificate = key_hash & mask;
		ha[index] = ret1;
		hb[index] = ret2;
		certs[index] = certificate;
		return key_hash;
		//cout<<key_hash<<"  "<<ret1<<"  "<<ret2<<"   "<<certificate<<endl;
	}

	/*
	 generate the input for simulation
	 */
	void GenerateInput() {
		cout << "generate input ... ... " << endl;

		//define the key_type of the node, use 0 - (SENSOR_NUMBER-1) to represent the node value
		DefinedType type(OTHELLO_OUTPUT_NUMBER);
		map<int, string> nodes_certificates;
		int *othello_key = new int[SENSOR_NUMBER_];
		unsigned long * othello_value = new unsigned long[SENSOR_NUMBER_];

		//initial the bad nodes according to the node number
		GenerateMaliciousNode(SENSOR_NUMBER_, MALICIOUS_NODE_NUMBER_,
				sensor_nodes_, m_nodes);

		//initial the location,pub_key and its certificate of sensors nodes
		srand((int) time(0));
		double mean = SENSOR_NUMBER_ / 2;
		double vari = SENSOR_NUMBER_ / 10;

		for (int i = 0; i < SENSOR_NUMBER_; i++) {
			othello_key[i] = i;
			sensor_nodes_[i].SetLocation(i);
			sensor_nodes_[i].local_time_ = 1.0;

			//generate the pub_key for the sensor node
			string* pub_key_result = GeneratePubKey(KEY_BITS_, KEXP);
			string pub_key = pub_key_result[0];
			//cout << pub_key << endl;
			string pub_key_hash = GeneratePubKeyHash(pub_key, hash_type_);

			//cout<<pub_key_hash<<endl;
			unsigned char* pub_key_certificate = new unsigned char[KEY_BITS_];
			SignData(hash_type_, (unsigned char*) pub_key_hash.c_str(),
					rsa_private_key_, pub_key_certificate, out_len);
			unsigned int check_sum = GetCheckSum(pub_key_certificate);

			OthelloOutput output = GenerateOthelloOutput(SENSOR_NUMBER_,
					check_sum);
			unsigned long output_value =
					*reinterpret_cast<unsigned long*>(&output);
			othello_value[i] = output_value;

			//verify data
			VerifyData(hash_type_, pub_key_hash, pub_key_certificate,
					rsa_pub_key_, out_len);
			pub_key_certificate_[i] = pub_key_certificate;
			pub_key_[i] = pub_key;
			pub_key_hash_[i] = pub_key_hash;
			string h = pub_key_hash_[i];
			unsigned char* c = pub_key_certificate_[i];
			int result = server_node_.VerifyCertificate(h, c, rsa_pub_key_,
					hash_type_, out_len);
			if (result != 1)
				cout << i << " error" << endl;
			idle_from_time_[i] = 0.0;
		}
		Othello<int, unsigned long> global_othello(othello_key, SENSOR_NUMBER_,
				othello_value);
		cout << "generate over" << endl;

		Server<int, string, OthelloOutput> server(pub_key_, pub_key_hash_,
				pub_key_certificate_, 0, SENSOR_NUMBER_);
		server_node_ = server;
		server_node_.SetGlobalOthello(global_othello);
		server_node_.local_time_ = 1.0;
		cout << "server node is over" << endl;
		for (int i = 0; i < SENSOR_NUMBER_; i++)
			sensor_nodes_[i].global_othello_ = global_othello;

		//CheckSum(pub_key_certificate_, global_othello);

		//generate the event time
		cout << "generate event time" << endl;
		event_time_ = GeneratePoissonDistribution(POISSON_MEAN_, MAX_CLOCK_);
		time_sum_[0] = 0;
		for (int i = 1; i < MAX_CLOCK_ + 1; i++) {
			time_sum_[i] = time_sum_[i - 1] + event_time_[i - 1];
		}
		event_sum_ = time_sum_[MAX_CLOCK_];
		//generate the corresponding event, including the sender and the receiver
		input_data_ = GenerateInputData(distribution_type_, event_sum_,
				SENSOR_NUMBER_, mean, vari);
		cout << "input_data generate over" << endl;
		cout << "event sum: " << event_sum_ << endl;
	}

	/**
	 * check the correctness of Othello
	 */
	void CheckSum(unsigned char** pub_key_certificate_,
			Othello<int, unsigned long> global_othello) {
		for (int i = 0; i < SENSOR_NUMBER_; i++) {
			unsigned long output = global_othello.query(i);
			unsigned int check_sum =
					(*reinterpret_cast<OthelloOutput*>(&output)).check_sum;
			unsigned int generate_check_sum = GetCheckSum(
					pub_key_certificate_[i]);
			if (check_sum == generate_check_sum) {
				cout << "checksum pass" << endl;
			} else {
				cout << "node " << i << " fail" << endl;
				cout << check_sum << "   " << generate_check_sum << endl;
			}
		}
	}

	/*
	 * use discrete event simulation method to simulate the fast verification
	 */
	void FastVerificationSimulation(string event_time_path,
			string bad_event_path, string trust_path, bool has_trust) {
		//push event into priority of sensors
		ofstream event_f(event_time_path);
		ofstream trust_f(trust_path);
		ofstream bad_num_f(bad_event_path);
		int system_clock = 0;
		int update_num = 1;
		double *local_time = new double[SENSOR_NUMBER_];
		fill(local_time, local_time + SENSOR_NUMBER_, 0.0);
		list<int> event_sensors;
		int n = 0;
		while (system_clock < MAX_CLOCK_) {
			int begin_index = time_sum_[system_clock];
			int num = event_time_[system_clock];
			for (int i = 0; i < num; i++) {
				n += 1;
				int event_index = begin_index + i;
				input_data_[event_index].begin_time = ((double) system_clock)
						+ 1.0;
				input_data_[event_index].comp_time = ((double) system_clock)
						+ 1.0;
				DataInputFormat &event_data = input_data_[event_index];
				int receiver_node = event_data.receiver_node;
				//push this event into priority queue of sensor receiver_node and set local time
				sensor_nodes_[receiver_node].event_queue_.push(event_data);
				if (system_clock == 1) {
					local_time[receiver_node] = 1.0;
					event_sensors.push_back(receiver_node);
				}
			}
			system_clock += 1;
		}
		cout << n << endl;
		cout << "event push to priority queue over" << endl;
		//schedule event in different sensors
		double global_time = 1.0;
		double max_time = 20.0 * MAX_CLOCK_;
		//schedule sensors
		while (fabs(global_time - max_time) >= eps) {
			//there are events that need to be dealt
			DealEvents(global_time, event_f, trust_f, has_trust);
			//cout << "bad event " << bad_num << endl;
			bad_num_f << bad_num << endl;
			global_time = GetGlobalTime();
			if (global_time >= (UPDATE_INTERVAL * update_num)
					&& global_time < (UPDATE_INTERVAL * (update_num + 1))) {
				//cout<<"updateOthello: "<<endl;
				server_node_.UpdateOthello(has_trust);
				for (int i = 0; i < SENSOR_NUMBER_; i++)
					sensor_nodes_[i].global_othello_ =
							server_node_.global_othello_;
				update_num++;
			}
		}
		cout << "finish scheduling" << endl;
		event_f.close();
		bad_num_f.close();

		cout << "malicious node" << endl;
		for (int i = 0; i < MALICIOUS_NODE_NUMBER_; i++)
			cout << m_nodes[i] << " ";
		cout << endl;
		cout << bad_chosen_node << endl;
	}

	void DealEvents(double global_time, ofstream &f, ofstream & trust_f,
			bool has_trust) {
		for (int i = 0; i <= SENSOR_NUMBER_; i++) {
			int node_id = i;
			if (node_id != SENSOR_NUMBER_) {
				DealSensor(i, global_time, f, trust_f, has_trust);
			} else {
				DealServer(global_time, f, trust_f, has_trust);
				//cout << "deal server" << endl;
			}
		}
	}

	void DealSensor(int node_id, double global_time, ofstream &f,
			ofstream & trust_f, bool has_trust) {
		while (!sensor_nodes_[node_id].event_queue_.empty()) {
			DataInputFormat event = sensor_nodes_[node_id].event_queue_.top();
			double event_time = event.begin_time;
			if (event.queVeriFini == 1)
				event_time = event.verify_time;
			double local_time = sensor_nodes_[node_id].local_time_;
			double t = max(event_time, local_time);
			if (fabs(t - global_time) < eps) {
				//equal
				sensor_nodes_[node_id].ScheduleEvent(event, pub_key_,
						pub_key_hash_, pub_key_certificate_, SENSOR_NUMBER_, t,
						m_nodes, MALICIOUS_NODE_NUMBER_, has_trust);
				//cout << "schedule event over" << endl;
				sensor_nodes_[node_id].event_queue_.pop();
				DealtEvent(event, f, trust_f, has_trust);
			} else {
				break;
			}
		}
	}

	void DealServer(double global_time, ofstream &f, ofstream &trust_f,
			bool has_trust) {
		while (!server_node_.event_queue_.empty()) {
			DataInputFormat event = server_node_.event_queue_.top();
			double event_time = event.begin_time;
			if (event.queVeriFini == 1)
				event_time = event.verify_time;
			double local_time = server_node_.local_time_;
			double t = max(event_time, local_time);
			if (fabs(t - global_time) < eps) {
				server_node_.ScheduleEvent(event, pub_key_, pub_key_hash_,
						pub_key_certificate_, SENSOR_NUMBER_, t, rsa_pub_key_,
						hash_type_, out_len);
				//cout << "schedule event over" << endl;
				server_node_.event_queue_.pop();
				DealtEvent(event, f, trust_f, has_trust);
			} else {
				break;
			}
		}
	}

	void DealtEvent(DataInputFormat& event, ofstream &f, ofstream &trust_f,
			bool has_trust) {
		if (event.queVeriFini == 1) {
			if (event.verify_node == SENSOR_NUMBER_) {
				//insert event to server node
				server_node_.event_queue_.push(event);
				//successfully insert receiver's certificate to sender node
			} else {
				if (event.verify_node >= 0
						&& event.verify_node < SENSOR_NUMBER_) {
					//cout << "update event verify node" << event.verify_node<< endl;
					if (has_trust) {
						vector<int> ve =
								sensor_nodes_[event.receiver_node].bad_node;
						if (find(ve.begin(), ve.end(), event.verify_node)
								!= ve.end()) {
							event.verify_node = SENSOR_NUMBER_;
							server_node_.event_queue_.push(event);
						} else {
							sensor_nodes_[event.verify_node].event_queue_.push(
									event);
						}
					} else {
						sensor_nodes_[event.verify_node].event_queue_.push(
								event);
					}
					//cout << "update event verify node over" << endl;

				} else {
					cout << "verify node error" << endl;
					exit(-1);
				}
			}
		} else {
			if (event.queVeriFini == 2) {
				//the event is finished
				int verify_node = event.verify_node;
				if (verify_node != SENSOR_NUMBER_) {
					bool is_verify_corr = event.isVeriCorr;
					//cout << is_verify_corr << " update trust value" << endl;
					if (!is_verify_corr)
						bad_num += 1;
					if (has_trust) {
						server_node_.UpdateTrust(event.verify_node,
								event.receiver_node, is_verify_corr, trust_f);
						//cout<<m_nodes[1]<<endl;
						//server_node_.PrintTrust(m_nodes[1]);
						if (find(m_nodes, m_nodes + MALICIOUS_NODE_NUMBER_,
								verify_node)
								!= (m_nodes + MALICIOUS_NODE_NUMBER_))
							bad_chosen_node += 1;
					}
				} else {
					if (server_node_.UpdateStoreNodes(event.send_node,
							event.receiver_node)) {
						bool save_corr =
								sensor_nodes_[event.receiver_node].SaveCertificates(
										event.send_node,
										pub_key_certificate_[event.send_node]);
					}
				}
				//if (find(m_nodes, m_nodes + MALICIOUS_NODE_NUMBER_,verify_node) != m_nodes+MALICIOUS_NODE_NUMBER_)

				//cout << event.begin_time << " " << event.end_time << " "<<
				//	event.verify_node << " "<<(event.end_time-event.begin_time)<<endl;
				f << (event.end_time - event.begin_time) <<endl;
			}
		}
	}

	/*
	 * globalTime: the earliest time of the event in the whole system
	 */
	double GetGlobalTime() {
		double max_time = 20.0 * MAX_CLOCK_;
		double global_time = max_time;
		for (int i = 0; i < SENSOR_NUMBER_; i++) {
			double t = max_time;
			if (!sensor_nodes_[i].event_queue_.empty()) {
				double local_time = sensor_nodes_[i].local_time_;
				double event_time =
						sensor_nodes_[i].event_queue_.top().begin_time;
				if (sensor_nodes_[i].event_queue_.top().queVeriFini == 1)
					event_time =
							sensor_nodes_[i].event_queue_.top().verify_time;
				t = max(local_time, event_time);
			}
			global_time = min(t, global_time);
		}
		double t = max_time;
		if (!server_node_.event_queue_.empty()) {
			double local_time = server_node_.local_time_;
			double event_time = server_node_.event_queue_.top().comp_time;
			if (server_node_.event_queue_.top().queVeriFini == 1)
				event_time = server_node_.event_queue_.top().verify_time;
			t = max(local_time, event_time);
		}
		global_time = min(t, global_time);
		//cout << "global time: " << global_time << endl;
		return global_time;
	}

	void AnalyzeTime(string time_path) {
		ifstream time_f(time_path);
		double t;
		vector<double> e_time;
		while (!time_f.eof()) {
			time_f >> t;
			e_time.push_back(t);
		}
		int size = e_time.size()-1;
		double* result = new double[size];
		for (int i = 0; i < size; i++) {
			result[i] = e_time[i];
		}
		GetParaForProbability(result, size);
	}

	/*
	 simulate verification for the test
	 if node receive the public key and its certificate, it asks server to verify this certificate
	 */
	void VerificationSimulation(string path) {
		double server_idle_time = 0.0;  //define the idle time of the server
		int system_clock = 0;  //set the begining clock is 1
		while (system_clock < MAX_CLOCK_) {
			int begin_index = time_sum_[system_clock];
			int num = event_time_[system_clock]; //get the event sum in this clock
			// if(event_time[clock_size-1] != num) {cout<<"couting error "<<endl;}
			for (int i = 0; i < num; i++) {
				int event_index = begin_index + i;
				DataInputFormat & event_data = input_data_[event_index];
				event_data.begin_time = event_data.real_begin_time =
						system_clock;
				int sender = event_data.send_node;
				// int receiver = event_data.receiver_node;

				string pub_key_hash = pub_key_hash_[sender];
				unsigned char* pub_key_certificate =
						new unsigned char[KEY_BITS_];
				pub_key_certificate = pub_key_certificate_[sender];
				//cout<<"sender "<<sender<<endl;
				unsigned long veri_start_s = clock();
				if (find(server_node_.stored_certificate_nodes.begin(),
						server_node_.stored_certificate_nodes.end(), sender)
						== server_node_.stored_certificate_nodes.end()) {
					int verify_result = server_node_.VerifyCertificate(
							pub_key_hash, pub_key_certificate, rsa_pub_key_,
							hash_type_, out_len);
					if (verify_result != 1)
						cout << sender << " verify error" << endl;
					server_node_.SetStoredCertificateNodes(sender);
				} else {
					unsigned char* real_certificate =
							pub_key_certificate_[sender];
					int l = strlen((char*) real_certificate);
					//cout << "length " << l << endl;
					int result =
							(memcmp(pub_key_certificate, real_certificate, l)) ?
									1 : 0;
					if (result != 0)
						cout << endl << "wrong certificate, error!" << endl;
				}

				unsigned long veri_stop_s = clock();
				double veri_time_interval = (veri_stop_s - veri_start_s)
						/ double(CLOCKS_PER_SEC) * 1000;
				double verify_time = veri_time_interval;
				//cout<<"verify_time "<<veri_time_interval<<endl;
				if ((server_idle_time - system_clock) > 0.0) {
					event_data.real_begin_time = server_idle_time;
				}
				double end_time = event_data.real_begin_time + verify_time;
				event_data.end_time = end_time;
				server_idle_time = end_time;
			}
			system_clock += 1;
		}
		AnalysisResult(path);
	}

	void AnalysisResult(string file_name) {
		double run_time_array[event_sum_];
		ofstream time_file(file_name);
		for (int i = 0; i < event_sum_; i++) {
			//cout << i << " ";
			//cout << input_data_[i].begin_time;
			//cout << " " << input_data_[i].real_begin_time;
			//cout << " " << input_data_[i].verify_time;
			//cout << " " << input_data_[i].end_time;
			//cout << " " << input_data_[i].send_node;
			//cout << " " << input_data_[i].receiver_node;
			//cout << " " << input_data_[i].target_node;
			double run_time = input_data_[i].end_time
					- input_data_[i].begin_time;
			//cout << " " << run_time << endl;
			run_time_array[i] = run_time;
			time_file << run_time <<endl;
		}
		time_file.close();
		GetParaForProbability(run_time_array, event_sum_);
	}

	/*
	 * test encryption performance
	 */
	void TestSignVerifyTime(int type, string private_rsa_key,
			string public_rsa_key, int count, string encryption_path,
			string decryption_path) {
		double *encrypt_time = new double[count];
		double *decrypt_time = new double[count];
		ofstream encryption_time_file(encryption_path);
		ofstream decryption_time_file(decryption_path);
		for (int i = 0; i < count; i++) {
			string* pub_key_result = GeneratePubKey(KEY_BITS_, KEXP);
			string pub_key = pub_key_result[0];
			string pub_key_hash = GeneratePubKeyHash(pub_key, hash_type_);
			//cout<<pub_key_hash<<endl;
			clock_t encryption_start_time = clock();
			unsigned int out_len;
			unsigned char* pub_key_certificate = new unsigned char[KEY_BITS_];
			//SignData(type, pub_key_hash, private_rsa_key, pub_key_certificate,
			//out_len);
//			char* public_key_certificate = Encryption(
//					(unsigned char*) pub_key_hash.c_str(), private_rsa_key);
			//cout<<pub_key_certificate<<endl;
			clock_t encryption_stop_time = clock();
			double time_interval =
					(encryption_stop_time - encryption_start_time)
							/ double(CLOCKS_PER_SEC) * 1000;
			//cout<<"per encrypted time "<<time_interval<<endl;
			encrypt_time[i] = time_interval;
			encryption_time_file << time_interval << " ";
			clock_t decryption_start_time = clock();
//			Decryption((char *) pub_key_hash.c_str(), public_key_certificate,
//					public_rsa_key);
			int result = VerifyData(type, pub_key_hash, pub_key_certificate,
					public_rsa_key, out_len);
			clock_t decryption_stop_time = clock();
			double decryption_time = (decryption_stop_time
					- decryption_start_time) / double(CLOCKS_PER_SEC) * 1000;
			//cout<<"per decryption time "<<decryption_time<<endl;
			decrypt_time[i] = decryption_time;
			decryption_time_file << decryption_time << " ";
		}
		encryption_time_file << endl;
		encryption_time_file.close();
		decryption_time_file << endl;
		decryption_time_file.close();
		GetParaForProbability(encrypt_time, count);
		GetParaForProbability(decrypt_time, count);
	}

	/*
	 analyze the query time performance and verify time performance
	 */
	void AnalysisQueryAndVerify(Othello<int, unsigned long> global_othello) {
		cout << "query_para result ";
		query_para_ = SimulateParaForQuery(global_othello, SENSOR_NUMBER_,
				10000);
		cout << endl;
		cout << "verify_para result ";
		cout << endl;
	}

//test othello
	void TestOtello() {
		string key[] = { "ican", "hope" };
		int value[] = { 1, 3 };
		Othello<string, int> othello(key, 2, value);
		cout << "othello test over" << endl;
	}
}
;

