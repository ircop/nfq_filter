#include "config.h"

Config::Config( std::string filename )
{
	this->filename = filename;
	
	std::ifstream cfile( filename );
	if( !cfile.is_open() ) {
		printf("Can't open config file!\n");
		exit(-1);
	}
	
	std::string buf;
	
	while( std::getline (cfile, buf ) )
	{
		if( buf.length() > 0 )
		{
			buf.erase(remove_if(buf.begin(), buf.end(), isspace), buf.end());
			
			if( buf[0] == '#' || buf[0] == ';' || ( buf[0] == '/' && buf[1] == '/' ) || buf[0] == '=' )
				continue;
			
			std::size_t i = buf.find_last_of('=');
			if( i == std::string::npos )
				continue;
			if( i+1 == buf.length() )
				continue;
			
			
			// var name
			std::string key = buf.substr(0, i);
			if( key == "" ) continue;
			// var value
			std::string value = buf.substr( i+1, buf.length() );
			if( value == "" ) continue;
			
//			std::cout << "Line parsed:\t'" << key << "'\t->\t'" << value << "'" << std::endl;
			this->params[key] = value;
		}
	}
}


bool Config::getParam( std::string name, std::string &param )
{
	if( name == "" )
		return false;
	
	std::unordered_map<std::string,std::string>::const_iterator found = this->params.find( name );
	if( found != this->params.end() ) {
		param = found->second;
		return true;
	} else {
		return false;
	}
}

bool Config::getParam( std::string name, short unsigned int &param )
{
	if( name == "" )
		return false;
	
	std::unordered_map<std::string,std::string>::const_iterator found = this->params.find( name );
	if( found != this->params.end() ) {
		std::string param_str = found->second;
		
		char *temp;
		short unsigned int _val = strtol( param_str.c_str(), &temp, 0);
		if( *temp != '\0' ) {
			printf("Can't convert '%s' parameter to int: '%s'\n", name.c_str(), param_str.c_str() );
			exit(-1);
		}
		param = _val;
	} else {
		return false;
	}
}

bool Config::getParam( std::string name, int &param )
{
	if( name == "" )
		return false;
	
	std::unordered_map<std::string,std::string>::const_iterator found = this->params.find( name );
	if( found != this->params.end() ) {
		std::string param_str = found->second;
		
		char *temp;
		int _val = strtol( param_str.c_str(), &temp, 0);
		if( *temp != '\0' ) {
			printf("Can't convert '%s' parameter to int: '%s'\n", name.c_str(), param_str.c_str() );
			exit(-1);
		}
		param = _val;
	} else {
		return false;
	}
}
