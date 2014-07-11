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

bool Config::getQueues(int &from, int &to)
{
	std::string mq;
	if( this->getParam( "multiqueues", mq ) ) {
		// multi-queues
		mq.erase(remove_if(mq.begin(), mq.end(), isspace), mq.end());		// trim
		std::size_t i = mq.find_last_of(':');
		if( i == std::string::npos )
			return false;
		if( i+1 == mq.length() )
			return false;
		
		// start
		std::string f = mq.substr(0, i);
		// end
		std::string t = mq.substr( i+1, mq.length() );
		
		char *temp;
		int _val = strtol( f.c_str(), &temp, 0 );
		if( *temp != '\0' ) {
			printf("Config: Multiqueue starting queue num is not numeric: %s\n", f.c_str() );
			exit(-1);
		}
		from = _val;
		_val = strtol( t.c_str(), &temp, 0 );
		if( *temp != '\0' ) {
			printf("Config: Multiqueue ending queue num is not numeric: %s\n", t.c_str() );
			exit(-1);
		}
		to = _val;
		
		if( from < 0 || to < 0 ) {
			printf("Config: Queue num can't be < 0 (%s)\n", mq.c_str() );
			exit(-1);
		}
		
		if( to <= from ) {
			printf("Config: Ending queue must be > starting queue num (%s)\n", mq.c_str() );
			exit(-1);
		}
		
		return true;
	} else {
		return false;
	}
}

