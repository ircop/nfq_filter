#ifndef __sender_h
#define __sender_h

#include <stdio.h>
#include <stdlib.h>
#include <cstring>
#include <errno.h>
#include <stdio.h>
#include <string>
#include <sys/socket.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

class CSender {
	public:
		CSender( int debug, std::string url );
		void Redirect(int user_port, int dst_port, char *user_ip, char *dst_ip, uint32_t acknum, uint32_t seqnum, int f_psh);
		void sendPacket(char *ip_from, char *ip_to, int port_from, int port_to, uint32_t acknum, uint32_t seqnum, const char *dt, int f_reset, int f_psh);
	
	private:
		unsigned short csum(unsigned short *ptr, int nbytes);
		int debug;
		int s;
		std::string redirect_url;
		std::string rHeader;
};


#endif
