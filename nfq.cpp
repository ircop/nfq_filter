//#define __USE_BSD
#include "sender.h"
#include <getopt.h>
#include <iostream>
#include <fstream>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>
//#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <linux/netfilter.h>
#include <unordered_map>
#include <pthread.h>		// for threading
#include <boost/regex.hpp>
#include <boost/program_options.hpp>
#include <time.h>
#include <sys/stat.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "parser.h"		// HTTP parser functions

#define NF_IP_PRE_ROUTING   0
#define NF_IP_LOCAL_IN 1
#define NF_IP_FORWARD 2
#define NF_IP_LOCAL_OUT 3
#define NF_IP_POST_ROUTING 4

#define iphdr(x)	((struct iphdr *)(x))
#define tcphdr(x)	((struct tcphdr *)(x))

#define PREROUTING 0
#define POSTROUTING 4
#define OUTPUT 3
#define BUFSIZE 4096

#define PROG_VER "0.11"
#define PROG_NAME "nfq_filter"

using namespace std;
namespace po = boost::program_options;

typedef struct {
	unsigned long size,resident,share,text,lib,data,dt;
} statm_t;

// prototypes:
void print_options(void);		// print runtime options
void on_quit(void);			// on normal exit callback function
void read_config( std::string file );	// reading config file
void read_domains();	// reading domains file
void read_urls();	// reading urls file
inline std::string trim( std::string& str );
void *tcap_packet_function( void *threadarh );
void *twrite_log_function( void *);
void writelog( string filename, char *toprint );
short int netlink_loop(unsigned short int queuenum);
static int nfqueue_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);
char *get_src_ip_str( char *payload );
char *get_dst_ip_str( char *payload );
int get_tcp_src_port(char *payload);
int get_tcp_dst_port(char *payload);
unsigned long djb2( unsigned char *str );
void read_mem( statm_t &result );

void getData( unsigned char* data, int size, char *result );
void printData( unsigned char* data, int size );

// global vars:
std::string domains_file = "/etc/nfq/domains";
std::string urls_file = "/etc/nfq/urls";
std::string logfilename = "/tmp/nfq_filter.log";
std::string redirect_url = "http://google.com";
std::unordered_map<std::string, int> domains;
std::unordered_map<unsigned long, std::string> urls;
long int filtered, captured;
char tmp[4096];
CSender *Sender;

int debug = 1;
unsigned short int queuenum;

int main( int argc, char * argv[] )
{
	filtered = 0;
	// http://monoutil.googlecode.com/svn-history/r24/trunk/packet_engine.c
	int ret = 0;
//	unsigned short int queuenum = 0;		// queue number to read
	int daemonized = 0;
	std::string config_file("/etc/nfq_filter.cfg");
	
	// check input params
	if( argc < 2 ) {
		print_options();
		exit( -1 );
	}
	
	// check for root user
	if( getuid() != 0 ) {
		fprintf(stderr, "\n%s Version %s\n", PROG_NAME, PROG_VER);
		fprintf(stderr, "This program should run as root only.\n");
		exit(-1);
	}
	
	// register function to be called at normal program termination
	ret = atexit(on_quit);
	if( ret ) {
		fprintf( stderr, "Cannot register exit function, terminating.\n");
		exit(-1);
	}
	
	const struct option longopts[] =
	{
		{"config",	1,	0,	'c'},
		{"version",	0,	0,	'v'},
		{"help",	0,	0,	'h'},
		{"daemonize",	0,	0,	'd'},
//		{"logfile",	1,	0,	'l'},
//		{"queue",	1,	0,	'q'},
		{0,0,0,0},
	};
	
	int index;
	int iarg=0;
	queuenum = 0;
	while( iarg != -1 )
	{
		iarg = getopt_long(argc, argv, "c:vhd", longopts, &index);
		switch(iarg) {
			case 'c':
				if( optarg ) {
					config_file = string(optarg);
				}
				break;
			case 'h':
				print_options();
				exit(-1);
//			case 'q':
//				if( optarg ) {
//					queuenum = (unsigned short int)atoi(optarg);
//				}
//				break;
//			case 'l':
//				logfilename = optarg;
//				break;
//			case 'D':
//				daemonized = 1;
//				break;
			case 'v':
				fprintf(stderr, "%s ver. %s\n", PROG_NAME, PROG_VER);
				exit(-1);
			case '?':
				fprintf(stderr, "\nInvalid option or missing parameter, use `nfq -h` for hepl.\n\n");
				exit(-1);
		}
	}
	
	read_config( config_file );
	sprintf( tmp, "--------------------------\nStarting program.\n\nQueue:\t\t%i\nLog file:\t%s\nDebug:\t\t%i\n", queuenum, logfilename.c_str(), debug ) ;
	printf( "%s", tmp );
	writelog( logfilename, tmp );
	
	// Initialization;
	// Reading domain list:
	read_domains();
	read_urls();
	fprintf(stderr, "\nURLs and Domains files reading done.\n");
	
	Sender = new CSender( debug, redirect_url );
	
	// Starting threads
	pthread_t tcap_packet, twrite_log;
	ret = pthread_create(&tcap_packet, NULL, tcap_packet_function, (void *) &queuenum);
	if( ret ) {
		printf("- ERROR(1): return code from pthread_create: %d\n", ret);
		exit(-1);
	}
	ret = pthread_create(&twrite_log, NULL, twrite_log_function, (void *)NULL);
	if( ret ) {
		printf("- ERROR(2): return code from pthread_create: %d\n", ret);
		exit(-1);
	}
	
	
	
	statm_t mem;
	char buf[128];
	while(1){
		sleep(100);
		
		read_mem(mem);
		sprintf(buf, "Parent memory usage:\n%ld\n", mem.size );
		writelog(logfilename, buf);
	}
	
	pthread_exit(NULL);
//	fprintf(stderr, "\nqnum: %d\n", queuenum );
}

void read_config( std::string file )
{
	po::options_description config;
	po::variables_map vm;
	
//	printf("Reading config file: %s...\n", file.c_str() );
	
	std::ifstream cfile(file.c_str());
	if( !cfile ) {
		printf("Can't read config: '%s'\n", file.c_str() );
		exit( -1 );
	}
//	unsigned short int q_num;
	config.add_options()
		("queue", po::value<unsigned short int>(&queuenum)->default_value(0), "Queue number")
		("logfile", po::value<std::string>(&logfilename)->default_value(logfilename.c_str()), "Log filename")
		("debug", po::value<int>(&debug)->default_value(debug), "Debugging output")
		("domainlist", po::value<std::string>(&domains_file)->default_value("/etc/nfq/domains"), "Domain list file")
		("urllist", po::value<std::string>(&urls_file)->default_value("/etc/nfq/urls"), "Url list file")
		("redirect_url", po::value<std::string>(&redirect_url)->default_value("http://google.com"), "URL for redirects");
	
	vm = po::variables_map();
	po::store( po::parse_config_file( cfile, config ), vm );
	cfile.close();
	po::notify(vm);
	
	if( debug < 0 || debug > 4 ) {
		debug = 1;
	}
	
	return;
}

//void read_domains( std::unordered_map<std::string, int> d )
void read_domains()
{
	// reading domain names file 'domains.txt'
	ifstream dfile;
	string dline;
//	dfile.open("domains.txt");
	dfile.open( domains_file );
	if( !dfile )
	{
		fprintf(stderr, "\nCan not open domains.txt!\n");
		return;
	}
	
	while( !dfile.eof() ) {
		getline(dfile, dline);
		dline = trim(dline);
		if( dline.length() > 3 ) {
			domains[dline] = 1;
		}
	}
	
	// print out domains:
//	for( std::unordered_map<std::string, int>::iterator it = d.begin(); it != d.end(); ++it ) {
//		std::cout << " [" << it->first << ", " << it->second << "]";
//		std::cout << endl;
//	}
//
//	if( d.find( string("zebradudka.com") ) != d.end() ) {
//		fprintf(stderr, "\nDomain found!\n");
//	} else {
//		fprintf(stderr, "\nDomaint NOT found!\n");
//	}
	
	return;
}

void read_urls()
{
	// reading urls file 'urls.txt'
	ifstream ufile;
	string uline;
//	ufile.open("urls.txt");
	ufile.open( urls_file );
	if( !ufile )
	{
		fprintf(stderr, "\nCan not open urls.txt!\n");
		return;
	}
	
	while( !ufile.eof() ) {
		getline(ufile, uline);
		uline = trim(uline);
		
		unsigned long hash = djb2( (unsigned char *)uline.c_str() );
		
		if( uline.length() > 3 ) {
			urls[hash] = uline;
		}
	}
	
	// print out
//	for( std::unordered_map<unsigned long, std::string>::iterator it = urls.begin(); it != urls.end(); ++it ) {
//		std::cout << " [" << it->first << ", " << it->second << "] " << endl;
//	}
	
	return;
}

void print_options(void)
{
	printf("\n%s Version %s", PROG_NAME, PROG_VER);
	printf("\n\nSyntax: nfq <-c config_file> [ -h ] [ -d ]\n\n");
	printf("  -c\t\t- specify config file to read\n");
	printf("  -h\t\t- displays this help and exit.\n");
//	printf("  -q <0-65535>\t- listen to the NFQUEUE (as specified in --queue-num with iptables)\n");
//	printf("  -l <logfile>\t- specify an alternative log file\n");
	printf("  -d\t\t- run this program as daemon\n\n");
}


void on_quit(void)
{
//	printf("Program terminated.\n");
}

inline std::string trim( std::string& str )
{
	str.erase( 0, str.find_first_not_of(' '));
	str.erase( str.find_last_not_of(' ')+1);
	return str;
}

void *tcap_packet_function( void *threadarg )
{
	printf("Thread: sniffing packet...started.\n");
	netlink_loop(*(unsigned short int *) threadarg);
	pthread_exit(NULL);
}

void *twrite_log_function( void *)
{
	printf("Thread: write log file...started\n");
	
	statm_t mem;
	char buf[128];
	while(1){
		sleep(100);
		read_mem(mem);
		sprintf(buf, "%sFiltered: %lu\nCaptured: %lu\nMemory: %ld\n\n", "\n---- stats ----\n", filtered, captured, mem.size);
		writelog(logfilename, buf);
		/*
		read_mem(mem);
		sprintf(buf, "Self memory usage:\n%ld\n", mem.size );
		writelog(logfilename, buf);
		*/
	}
	pthread_exit(NULL);
}
void writelog( string filename, char *toprint ) {
	FILE *fd = fopen(filename.c_str(), "a");
	if( fd == NULL ) {
		printf("Unable to open log file.\n");
		exit(-1);
	}
	
	time_t now = time(0);
	struct tm tstruct;
	char b[80];
	tstruct = *localtime(&now);
	strftime(b, sizeof(b), "%d.%m.%Y %X", &tstruct );
	
	fprintf( fd, "\n%s:\n", b );
	fprintf( fd, "%s", toprint );
	
	printf( "%s", toprint );
	
//	print_values(fd);
	fflush(stdout);
	fclose(fd);
}

short int netlink_loop(unsigned short int queuenum)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd,rv;
	char buf[BUFSIZE];
	
	// open library handle
	h = nfq_open();
	if( !h ) {
		printf("Error during nfq_open()\n");
		exit(-1);
	}
	
	// unbind all existing nfq handlers for AF_INET
	if( nfq_unbind_pf(h, AF_INET) < 0 ) {
		printf("Error during nfq_unbind_pf()\n");
		exit(-1);
	}
	
	// bind queue connection handle to process packets
	if( nfq_bind_pf( h, AF_INET ) < 0 ) {
		printf("Error during nfq_bind_pf()\n");
		exit(-1);
	}
	printf("NFQ: Binding to queue '%hd'\n", queuenum);
	
	// create queue
	qh = nfq_create_queue(h, queuenum, &nfqueue_cb, NULL);
	if( !qh ) {
		printf("Error during nfq_create_queue()\n");
		exit(-1);
	}
	
	//set the amount of data to copy to userspace for each packet in queue
	if( nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0 ) {
		printf("Can't set packet copy mode ( nfq_set_mode() )\n");
		exit(-1);
	}
	
	// returns netlink handle associated to given queue handle.
	nh = nfq_nfnlh(h);
	
	// returns file descriptor for the netlink connection associated with the given queue connection handle.
	// Can be used for receiving the queue packets for processing.
	fd = nfnl_fd(nh);
	while( ( rv = recv(fd, buf, sizeof(buf), 0) ) && rv >= 0 ) {
		
		// triggers an associated callback function for the given packet received from the queue.
		// Packets can be read from the queue using nfq_fd() and recv().
		nfq_handle_packet(h, buf, rv);
	}
	
	// unbind before exit
	printf("NFQUEUE: unbinding from queue '%hd'\n", queuenum);
	nfq_destroy_queue(qh);
	nfq_close(h);
	return(0);
}

static int nfqueue_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
	struct nfqnl_msg_packet_hdr *ph;
	ph = nfq_get_msg_packet_hdr(nfa);

//	statm_t mem;
//	char bf[128];
//	read_mem(mem);
//	sprintf(bf, "Thread memory usage:\n%ld\n", mem.size );
//	writelog(logfilename, bf);

	
	// Process packet only if it's prerouting:
	if( ph && ph->hook == NF_IP_PRE_ROUTING ) {
		captured++;
		// processing packet
		int id=0;
		int size=0;
		char *full_packet;	// packet data
		
		unsigned char *data;
		int len=0;
		
		id = ntohl( ph->packet_id );
//		printf("hw_protocol: 0x%04x hook = %u id = %u \n", ntohs(ph->hw_protocol), ph->hook, id);
		size = nfq_get_payload(nfa, (unsigned char **)&full_packet);
		len = nfq_get_payload(nfa, &data);
		int id_protocol = full_packet[9];	// identify ip protocol
		
		int iphlen = iphdr(data)->ihl*4;
		int tcphlen = tcphdr(data+iphlen)->doff*4;
		int hlen = iphlen + tcphlen;
		int ofs = iphlen + sizeof(struct tcphdr);
		
		if( len == hlen ) {
			nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
			return(0);
		}
		
//		printf("\n----------------------------\n");
		// Process only TCP proto:
		if( id_protocol == IPPROTO_TCP ) {
			char src_ip[32], dst_ip[32];
			strcpy( src_ip, get_src_ip_str(full_packet) );
			strcpy( dst_ip, get_dst_ip_str(full_packet) );
			
//				printf("Packet (size: %d) captured: %s:%d -> %s:%d\n", size, get_src_ip_str(full_packet), get_tcp_src_port(full_packet), get_dst_ip_str(full_packet), get_tcp_dst_port(full_packet) );
//				printf("Packet (size: %d) captured: %s:%d -> %s:%d\n", size, src_ip, get_tcp_src_port(full_packet), dst_ip, get_tcp_dst_port(full_packet) );
//				printf("Headers: IP: %d, TCP:%d, FULL: %d; total: %d\n", iphlen, tcphlen, hlen, len);
			
			// parce tcp header:
			struct tcphdr* tcph;
			char *pkt_data_ptr = NULL;
			pkt_data_ptr = full_packet + sizeof(struct ip);
			tcph = (struct tcphdr *) pkt_data_ptr;
			
			char hdr[120];
			sprintf(hdr, "%c%c%c%c%c%c Seq: 0x%x Ack: 0x%x Win: 0x%x TcpLen: %d\n",
				(tcph->urg ? 'U' : '*'),(tcph->ack ? 'A' : '*'),(tcph->psh ? 'P' : '*'),
				(tcph->rst ? 'R' : '*'),(tcph->syn ? 'S' : '*'),(tcph->fin ? 'F' : '*'),
				ntohl(tcph->seq), ntohl(tcph->ack_seq),
				ntohs(tcph->window), 4*tcph->doff);
			
			///////
			char result[4096] = {0};
			//printData( (unsigned char*)full_packet + sizeof(struct ip) + (4*tcph->doff), size - (tcph->doff*4) - sizeof(struct ip) );
			getData( (unsigned char*)full_packet + sizeof(struct ip) + (4*tcph->doff), size - (tcph->doff*4) - sizeof(struct ip), result );
			std::string res = result;
			
//			if( debug == 3 ) {
			if( debug > 0 ) {
				// Print all packets shortly
				sprintf( tmp, "Packet (size %d): %s:%d -> %s:%d\nHeader:%s", size, src_ip, get_tcp_src_port(full_packet), dst_ip, get_tcp_dst_port(full_packet), hdr );
			}
			if( debug == 4 || debug == 2) {
				// Print all packets full info
				sprintf( tmp, "Packet (size %d): %s:%d -> %s:%d\nHeader:%sPacket:\n%s", size, src_ip, get_tcp_src_port(full_packet), dst_ip, get_tcp_dst_port(full_packet), hdr, res.c_str() );
			}
			
//			http_request r;
//			if( parse_http( res, &r ) ) {
//				printf("\nPacket parsed successful:\nMethod:\t\t'%s'\tHost:\t'%s'\nFull URL:\t\t'%s'\n", r.method.c_str(), r.host.c_str(), r.full_url.c_str());
//			}
			
			// if not parsed -> accept
//			nfq_set_verdict( qh, id, NF_ACCEPT, 0, NULL);
//			return(1);
			
			// Search GET in this result
//			boost::regex regEx("^(?:[\\s\\t]?+)(GET|HEAD|TRACE|POST|OPTIONS)(?:[\\s]+)(.*)(?:[\\s]+)HTTP/1.(?:0|1)(?:[\\s]+)\n(?:.*?)Host:(?:[\\s]+)((([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]).)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9-]*[A-Za-z0-9])|(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]).){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))(?:[\\s]+)\n(?:.*?)");
//			boost::regex regEx("^(?:[\\s\\t]?+)(GET|HEAD|TRACE|POST|OPTIONS)(?:[\\s]+)(.*)(?:[\\s]+)HTTP/1.(?:0|1)(?:\\s*)?\n(?:.*)?Host:(?:[\\s]+)((([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]).)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9-]*[A-Za-z0-9])|(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]).){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))(?:\\s*)?\n(?:.*?)\n");
//			boost::smatch matches;
			
			http_request r;
			if( !parse_http( res, &r ) ) {
				if( debug > 2 ) {
					writelog( logfilename, tmp );
				}
				nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
				return(0);
			}  else {
				//printf("Match: %s | %s | %s | \n", matches[1].str().c_str(), matches[2].str().c_str(), matches[3].str().c_str() );
				string host = r.host;
				string url = r.full_url;
				string method = r.method;
				string full_url = r.full_url;
				
				sprintf(tmp, "%sMethod: '%s', Host: '%s',URL: '%s'\n", tmp, method.c_str(), host.c_str(), url.c_str() );
				
				// Check in domain list
				if( domains.find( host ) != domains.end() ) {
					if( debug > 0 ) {
						sprintf(tmp, "%s%s", tmp, "Domain found! Blocking.\n");
						writelog(logfilename, tmp);
					}
					
					Sender->Redirect( get_tcp_src_port(full_packet), get_tcp_dst_port(full_packet),
						 /*user ip*/src_ip, dst_ip,
						 /*acknum*/ tcph->ack_seq, /*seqnum*/ tcph->seq,
						 /* flag psh */ (tcph->psh ? 1 : 0 ) );
					filtered++;
					nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
					return(0);
				} else {
//					printf("Domain not found (%s). Checking URL.\n", host.c_str());
						if( debug > 0 ) {
							sprintf( tmp, "%s\nFull url: %s\n", tmp, full_url.c_str());
						}
						// Get hash of this url
						unsigned long url_hash = djb2( (unsigned char*)full_url.c_str() );
						if( urls.find( url_hash ) != urls.end() ) {
//							printf("URL match (hash: %lu, url: %s), blocking!\n", url_hash, full_url.c_str() );
							if( debug > 0 )
							{
								sprintf( tmp, "%sURL match! hash: %lu, url: %s, blocking!\n", tmp, url_hash, full_url.c_str() );
								writelog( logfilename, tmp );
							}
							
							Sender->Redirect( get_tcp_src_port(full_packet), get_tcp_dst_port(full_packet),
									src_ip, dst_ip, tcph->ack_seq, tcph->seq,
									(tcph->psh ? 1 : 0 ) );
							filtered++;
							nfq_set_verdict( qh, id, NF_DROP, 0, NULL);
						}
//					}
				}
			}
		}
		if( debug == 3 || debug == 4 ) {
			writelog( logfilename, tmp );
		}
		// let the packet continue. NF_ACCEPT will pass the packet.
		nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
		return(0);
	} else {
		printf("NFQUEUE: can't get msg packet header.\n");
		return(1);	// 0=ok, 0+ = soft err, 0- = hard err
	}
	
	nfq_set_verdict(qh, ntohl( ph->packet_id ), NF_ACCEPT, 0, NULL);
	return(0);
}


char *get_src_ip_str( char *payload )
{
	struct ip *iph = (struct ip *) payload;
//	printf("SOURCE_IP: %s\n", inet_ntoa(iph->ip_src));
	return(inet_ntoa(iph->ip_src));
}
char *get_dst_ip_str( char *payload )
{
	struct ip *iph = (struct ip *) payload;
//	printf("DST_IP: %s\n", inet_ntoa(iph->ip_dst));
	return(inet_ntoa(iph->ip_dst));
}
int get_tcp_src_port(char *payload) {
	char *pkt_data_ptr = NULL;
	pkt_data_ptr = payload + sizeof(struct ip);
	struct tcphdr *tcph = (struct tcphdr *) pkt_data_ptr;
	return( ntohs(tcph->source) );
}
int get_tcp_dst_port(char *payload) {
	char *pkt_data_ptr = NULL;
	pkt_data_ptr = payload + sizeof(struct ip);
	struct tcphdr *tcph = (struct tcphdr *) pkt_data_ptr;
	return(ntohs(tcph->dest));
}

void getData( unsigned char* data, int size, char *result )
{
	for (u_int i=0; (i < size) ; i++)
	{
		sprintf( result, "%s%c", result, data[i]) ;
	}
	return;
}

void printData( unsigned char* data, int size )
{
	for (u_int i=0; (i < size) ; i++)
	{
		printf("%c", data[i]);
	}
	printf("\n");
	return;
}

// hashing
unsigned long djb2( unsigned char *str )
{
	unsigned long hash = 5381;
	int c;
	while( c = *str++ )
	{
		hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
	}
	return hash;
}

void read_mem(statm_t &result )
{
	unsigned long dummy;
	const char* statm_path = "/proc/self/statm";
	
	FILE *f = fopen( statm_path, "r" );
	if( !f ) {
		writelog( logfilename, (char *)"Cant open /proc/self/statm!\n");
		exit(-1);
	}
	
	if( 7 != fscanf(f,"%ld %ld %ld %ld %ld %ld %ld", &result.size,&result.resident,&result.share,&result.text,&result.lib,&result.data,&result.dt))
	{
		perror(statm_path);
		exit(-1);
	}
	
	fclose(f);
}

