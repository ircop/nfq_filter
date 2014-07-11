#ifndef __config_h
#define __config_h

#include <string>
#include <iostream>
#include <fstream>
#include <unordered_map>
#include <algorithm>

class Config
{
	public:
		Config( std::string filename );
//		void getParam( std::string name );
		bool getParam( std::string name, short unsigned int &param );
		bool getParam( std::string name, int &param );
		bool getParam( std::string name, std::string &param );
		bool getQueues(int &from, int &to);
	private:
		std::string filename;
		std::unordered_map<std::string, std::string> params;
};

#endif
