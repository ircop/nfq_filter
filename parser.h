#include <iostream>
#include <stdlib.h>
#include <string>
#include <sstream>
#include <algorithm>
#include <vector>
//#include <boost/regex.hpp>

typedef struct {
	std::string host, method, full_url;
} http_request;

bool parse_http( std::string pdata, http_request *req );

// get packet content by line
std::istream &getln( std::istream & in, std::string & out );
// remove multispaces
std::string spaces( std::string src );
std::string make_lowercase( const std::string& in );
