#include "parser.h"

std::vector<std::string> explode( std::string delim, std::string source );

bool parse_http( std::string pdata, http_request *req )
{
//	printf("--------\nparse_http call with packet:\n%s\n-----------\n", pdata.c_str() );
	
	std::string method, path, host, full_url, data;
	int http=1;
	int posf, pos, tam;
	
	/*
	// Find headers part ( before '\r\n' ):
	if( pos = pdata.find("\r\n\r\n",0) == std::string::npos )
		return false;						// packet has no http header part
	*/
	//data = pdata.substr(0, pos+1);
	data = pdata;
//	std::vector<std::string> strings = explode( "\r\n", pdata );
	std::vector<std::string> strings = explode( "\r\n", pdata );
	if( strings.size() < 2 ) {
//		printf("\nstrings.size()\n");
		return false;		// too low strings
	}
	
	
	// First string must me GET/POST/HEAD
	std::string line, tmp;
	line = strings.front();
	
	posf = line.find(" ", 0);	// first value before whitespace
	tmp = line.substr(0, posf);
//	printf("\n\nTRYING GET/POST/HEAD\n");
	if( tmp == "GET" || tmp == "POST" || tmp == "HEAD" ) {
		// valid request beginning
		method = tmp;
		
		// find path
		pos = line.find(" ", posf+1);
//		printf("\n\nTRYING first match\n");
		if( pos == std::string::npos ) {
//			printf("\npos == std::string::npos\n");
			return false;
		}
		tmp = line.substr( posf+1, pos-(posf+1) );
//		printf("\n\nTRYING 2ND MATCH\n");
		if( tmp == "" ) {
//			printf("\ntmp==''\n");
			return false;
		}
		path = tmp;
		
		
		// http ver.:
		posf = line.find("\r", pos);
//		printf("\n\nTRYING http ver\n");
		if( pos == std::string::npos ) {
//			printf("\npos == std::string::npos (2)\n");
			return false;
		}
		tmp = line.substr(pos+1, posf);
//		printf("\n\ntrying http/1.1\n");
		if( tmp == "HTTP/1.1" )
			http = 1;
		else if ( tmp == "HTTP/1.0" )
			http = 0;
		else {
//			printf("\nhttp1.0/0.0 failed\n");
			return false;
		}
	} else {
//		printf("\n NOT get/post/head\n");
		return false;
	}
	
//	printf("%s","Got method and http version.\n");
	
	// loop trough all other lines
//	for( std::string& str : strings ) {
	for( std::vector<std::string>::iterator it = strings.begin(); it != strings.end(); ++it ) {
		std::string str = *it;
		if( str.length() < 4 )
			continue;
//		printf("STRING: '%s'\n", str.c_str() );
		posf = str.find(" ", 0);
		if( posf != std::string::npos ) {
			// string with spaces
			tmp = str.substr(0, posf);
			if( make_lowercase( tmp ) == "host:" )
			{
				tmp = str.substr( posf+1 );
				// any spaces more?
				if( tmp.find(" ", 0) != std::string::npos ) {
					return false;
				}
				host = tmp;
//				printf("host found: '%s'\n", host.c_str());
				break;
			}
		}
	}
	
	// if http/1.1, path must begin with /
	if( http == 1 ) {
		if( path.substr(0,1) != "/" ) {
//			printf("\nvrong http 1.1 path\n");
			return false;
		}
		full_url = host + path;
	}
	
	if( http == 0 ) {
		// address begins with slash?
		if( path.substr(0,1) == "/" )
		{
			if( host != "" )
				full_url = host+path;
		} else {
			// path contains full url
			if( path.substr(0,4) == "http" ) {
				tmp = path.substr(0, 7);				// cut http://
				full_url = tmp;
				// get domain info
				if( pos = tmp.find("/") != std::string::npos ) {
					host = path.substr(0, pos);			// eg. http://www.ru/
				} else {
					host = path;					// eg. http://www.ru
				}
			}
		}
	}
	
	if( host == "" || path == "" || method == "" ) {
//		printf("\nno host/path/method\nhost: '%s' path: '%s' method: '%s'\n", host.c_str(), path.c_str(), method.c_str() );
		return false;
	}
	else
	{
		req->host = host;
		req->full_url = full_url;
		req->method = method;
		return true;
	}
}

std::istream &getln( std::istream & in, std::string & out )
{
	char c;
	
	while( in.get(c).good()) {
		if( c == '\n' ) {
			c = in.peek();
			if( in.good() ) {
				if( c == '\r' ) {
					in.ignore();
				}
			}
			break;
		}
		out.append(1, c);
	}
	return in;
}

std::string spaces( std::string src ) {
//	src.erase( std::unique(src.begin(), src.end(),[](char a, char b){ return a == ' ' && b == ' '; } ), src.end() );
	for( int j=0; j<src.length(); j++ ) {
		if( src[j] == ' ' && src[j+1] == ' ' )
			src.erase(j,1);
	}
	return src;
}

std::vector<std::string> explode( std::string delim, std::string source )
{
	std::vector<std::string> arr;
	size_t pos = 0;
	std::string token;
	
	int i=0;
	while((pos = source.find(delim)) != std::string::npos) {
		token = source.substr( 0, pos );
		source.erase(0, pos + delim.length() );
		token = spaces( token );
		arr.push_back(token);
		if( i > 7 )
			break;		// take only first 4 strings
		i++;
	}
	
	return arr;
}

std::string make_lowercase( const std::string& in )
{
	std::string out;
	
	std::transform( in.begin(), in.end(), std::back_inserter( out ), ::tolower );
	return out;
}
