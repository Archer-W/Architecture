#include <iostream>
#include <stdlib.h>
#include <bits/random.h>
#include <string>
#include<time.h>
#include<sys/timeb.h>
#include<ctime>
#include<fstream>
using std::ofstream;

#include <math.h>

#include"probability_para.h"
#include "data_input.h"
using namespace std;

#define random(x)  (rand()%x)
/*
 generate possion distribution by giving the mean and the generation number
 */
int* GeneratePoissonDistribution(double mean, int num) {
	default_random_engine generator;
	poisson_distribution<int> distribution(mean);

	int * p = new int[num + 1];
	int sum = 0;
	for (int i = 0; i < num; ++i) {
		int generate_result = distribution(generator);
		p[i] = generate_result;
		sum += generate_result;
		//cout<<i<<" "<<generate_result<<endl;
	}
	p[num] = sum;
	return p;
}

/*
 generate normal distribution
 */
int* GenerateNormalDistribution(double mean, double vari, int num) {
	random_device generator;
	normal_distribution<double> distribution(mean, vari);
	int *p = new int[num];
	for (int i = 0; i < num; i++) {
		int generate_result = distribution(generator);
		p[i] = generate_result;
		//cout<<i<<" "<<generate_result<<endl;
	}
	return p;
}

double GenerateNormalDistributionOne(double mean, double vari, double min,
		double max) {
	random_device generator;
	normal_distribution<double> distribution(mean, vari);
	double generate_result = distribution(generator);
	while ((generate_result - min) < 0.0 || (generate_result - max) > 0.0) {
		generate_result = distribution(generator);
	}
	return round(generate_result);
}

/*
 generate input data by the defined distribtion and number
 */
DataInputFormat* GenerateInputData(string distribution_name, int num,
		int sensor_num, double mean, double vari) {
	DataInputFormat* input_result = new DataInputFormat[num];
	// ofstream sender_out("/Users/archer/Documents/Code/KeyVerification/KeyVerification/sender_input_normal.txt");
	ofstream sender_out(
			"/Users/archer/Documents/Code/KeyVerification/KeyVerification/sender_input_random.txt");
	if (distribution_name == "normal_distribution") {
		for (int i = 0; i < num; i++) {
			//cout<<i<<" "<<p[i]<<endl;
			int sender = GenerateNormalDistributionOne(mean, vari, 0,
					sensor_num - 1);
			int receiver = GenerateNormalDistributionOne(mean, vari, 0,
					sensor_num - 1);
			while (receiver == sender)
				receiver = GenerateNormalDistributionOne(mean, vari, 0,
						sensor_num - 1);
			input_result[i] = DataInputFormat { 0.0, 0.0, 0.0, 0.0, 0.0, sender,
					receiver, 0, 0, true, true };
			//cout<<"sender: "<<sender<<" receiver: "<<receiver<<endl;
			sender_out << sender << " ";
		}
		sender_out.close();
	} else {
		if (distribution_name == "random_distribution") {
			srand((int) time(0));
			for (int i = 0; i < num; i++) {
				int sender = random(sensor_num);
				int receiver = random(sensor_num);
				input_result[i] = DataInputFormat { 0.0, 0.0, 0.0, 0.0, 0.0,
						sender, receiver, 0, 0, true, true };
				while (receiver == sender)
					receiver = GenerateNormalDistributionOne(mean, vari, 0,
							sensor_num - 1);
				//cout<<"sender: "<<sender<<" receiver: "<<receiver<<endl;
				sender_out << sender << " ";
			}
			sender_out.close();
		}
	}
	return input_result;
}

/*
 get mean and variance for gaussian distribution
 */
Para GetParaForProbability(double *data, int num) {
	double mean = 0.0;
	double vari = 0.0;
	double max_value = 0.0;
	double min_value = 100.0;
	for (int i = 0; i < num; i++) {
		mean += data[i];
		if (data[i] > max_value)
			max_value = data[i];
		if (data[i] < min_value)
			min_value = data[i];
	}
	mean = mean / num;
	double vari_sum = 0.0;
	for (int i = 0; i < num; i++) {
		double value = pow(data[i] - mean, 2.0);
		vari_sum += value;
	}
	vari = sqrt(vari_sum / num);
	cout << "mean " << mean << " vari " << vari << " max " << max_value
			<< " min " << min_value << endl;
	Para para = Para { mean, vari_sum, max_value, min_value };
	return para;
}

/*
 simulate the time for query data from othello
 */
Para SimulateParaForQuery(Othello<int, unsigned long> othello,
		int sensor_number, int sum) {
	struct timeb start_time, end_time;
	double time[sum];
	srand(unsigned(NULL));
	ofstream query_out(
			"/Users/archer/Documents/Code/KeyVerification/KeyVerification/query.txt");
	ofstream query_index(
			"/Users/archer/Documents/Code/KeyVerification/KeyVerification/index.txt");
	for (int i = 0; i < sum; i++) {
		int query_number = random(sensor_number);
		// cout<<query_number<<endl;
		unsigned long start_s = clock();
		unsigned long result = othello.query(query_number);
		OthelloOutput result_othello =
				*reinterpret_cast<OthelloOutput*>(&result);
		unsigned long stop_s = clock();
		double time_interval = (stop_s - start_s) / double(CLOCKS_PER_SEC)
				* 1000;  //millseconde
		//cout << "time: " << time_interval<< endl;
		time[i] = time_interval;
		query_out << time[i] << " ";
		query_index << i << " ";
	}
	query_out.close();
	query_index.close();
	Para para = GetParaForProbability(time, sum);
	return para;
}

/*
 simulate the time for verify the cerificate of a public key
 */
Para SimulateParaForVerify(string pub_key[], int sensor_num, int sum,
		int digest_length) {
	double *time = new double[sum];
	srand(unsigned(NULL));
	ofstream verify_out(
			"/Users/archer/Documents/Code/KeyVerification/KeyVerification/verify.txt");
	for (int i = 0; i < sum; i++) {
		int verify_number = random(sensor_num);
		string key = pub_key[verify_number];
		unsigned long start_s = clock();
		string md5_pub_key = GenerateMd5ForPubKey(key);
		unsigned long stop_s = clock();
		double time_interval = (stop_s - start_s) / double(CLOCKS_PER_SEC)
				* 1000;  //millseconde
		//cout << "time: " << time_interval<< endl;
		time[i] = time_interval;
		verify_out << time[i] << " ";
	}
	verify_out.close();
	Para para = GetParaForProbability(time, sum);
	return para;
}

