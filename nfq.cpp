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
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <linux/netfilter.h>
#include <unordered_map>
#include <mutex>
#include <pthread.h>
#include <mutex>
#include <time.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "parser.h"
#include "config.h"

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
void *tread_conf_function( void *);
void writelog( const char *fmt, ... );
short int netlink_loop(unsigned short int queuenum);
static int nfqueue_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);
char *get_src_ip_str( char *payload );
char *get_dst_ip_str( char *payload );
int get_tcp_src_port(char *payload);
int get_tcp_dst_port(char *payload);
unsigned long djb2( unsigned char *str );
void read_mem( statm_t &result );

void getData( unsigned char* data, int size, char *result );

// global vars:
std::string domains_file = "/etc/nfq/domains";
std::string urls_file = "/etc/nfq/urls";
std::string logfilename = "/tmp/nfq_filter.log";
std::string redirect_url = "http://google.com";
std::string debug_from_ip = "";
std::string debug_ip_file = "";
std::string pidfile = "";
int debug_ip = 0;
std::unordered_map<std::string, int> domains;
std::unordered_map<unsigned long, std::string> urls;
std::mutex Mutex;
long int filtered, captured;
char tmp[4096];
CSender *Sender;
FILE *f_log;
FILE *f_debug_ip;
int daemonized;

int debug = 1;
unsigned short int queuenum;

int main( int argc, char * argv[] )
{
	filtered = 0;
	int ret = 0;
	daemonized = 0;
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
			case 'v':
				fprintf(stderr, "%s ver. %s\n", PROG_NAME, PROG_VER);
				exit(-1);
			case 'd':
				daemonized = 1;
				break;
			case '?':
				fprintf(stderr, "\nInvalid option or missing parameter, use `nfq -h` for hepl.\n\n");
				exit(-1);
		}
	}
	
	read_config( config_file );
	sprintf( tmp, "\n--------------------------\nStarting program.\n\nQueue:\t\t%i\nLog file:\t%s\nDebug:\t\t%i\n", queuenum, logfilename.c_str(), debug ) ;
	
	f_log = fopen(logfilename.c_str(), "a");
	if( f_log == NULL ) {
		printf("%s\n", "Can't open logfile!\n");
		exit(-1);
	}
	if( pidfile == "" ) {
		printf("Can't read pid file from config!");
		exit(-1);
	}
	
	// Debug single ip?
	if( debug_from_ip != "" && debug_ip_file != "" ) {
		debug_ip = 1;
		f_debug_ip = fopen( debug_ip_file.c_str(), "a" );
		if( f_debug_ip == NULL ) {
			printf("%s\n", "Can't open debug single ip file!\n");
			exit(-1);
		}
		setlinebuf(f_debug_ip);
		fprintf( f_debug_ip, "%s", "Debug ip started...");
	}
	
	if( daemonized == 1 )
		printf( "%s", tmp );
	writelog( "%s", tmp );
	
	// Initialization;
	read_domains();
	read_urls();
	fprintf(stderr, "\nURLs and Domains files reading done.\n");
	
	// Daemonizing ( if needed )
	if( daemonized == 1 ) {
		printf("%s", "Daemonizing...\n");
		int pid = fork();
		if( pid == -1 )
		{
			printf("Error: daemonizing failed! (%s)\n", strerror(errno));
			return(-1);
		} else if (!pid) {
			// This is already child
			printf("Daemonized.\n");
			umask(0);
			setsid();
			chdir("/");
			close(STDIN_FILENO);
			close(STDOUT_FILENO);
			close(STDERR_FILENO);
			
		} else {
			// this is parent
			return pid;
		}
		
		// Write own pidfile
		FILE *fpid = fopen( pidfile.c_str(), "w+");
		if( fpid ) {
			fprintf(fpid, "%u", getpid());
			fclose(fpid);
		} else {
			writelog("%s", "Can't open pidfile! Exiting.\n");
			exit(-1);
		}
	}
	
	Sender = new CSender( debug, redirect_url );
	
	// Starting threads
	pthread_t tcap_packet, twrite_log, tread_conf;
	// Main thread
	ret = pthread_create(&tcap_packet, NULL, tcap_packet_function, (void *) &queuenum);
	if( ret ) {
		printf("- ERROR(1): return code from pthread_create: %d\n", ret);
		exit(-1);
	}
	// Log statistics thread
	ret = pthread_create(&twrite_log, NULL, twrite_log_function, (void *)NULL);
	if( ret ) {
		printf("- ERROR(2): return code from pthread_create: %d\n", ret);
		exit(-1);
	}
	// Reread config files
	ret = pthread_create( &tread_conf, NULL, tread_conf_function, (void *)NULL);
	if( ret ) {
		printf(" ERROR(3): return code from pthread_create: %d\n", ret);
		exit(-1);
	}
	
	
	
	statm_t mem;
	char buf[128];
	while(1){
		sleep(100);
		
		read_mem(mem);
		writelog( "Parent memory usage:\t%ld\n", mem.size );
	}
	
	fclose( f_log );
	if( debug_ip == 1 )
		fclose( f_debug_ip );
	
	pthread_exit(NULL);
}

void read_config( std::string file )
{
	Config *cfg = new Config ( file );
	
	if( !cfg->getParam( "queue", queuenum ) )
		queuenum = 0;
	if( !cfg->getParam("logfile", logfilename) )
		logfilename = "/tmp/nfq_filter.log";
	if( !cfg->getParam("pidfile", pidfile) )
		pidfile = "";
	if( !cfg->getParam("debug", debug) )
		debug = 1;
	if( !cfg->getParam("domainlist", domains_file ) )
		domains_file = "";
	if( !cfg->getParam("urllist", urls_file) )
		urls_file = "";
	if( !cfg->getParam("redirect_url", redirect_url) )
		redirect_url = "http://www.google.com";
	if( !cfg->getParam("debug_from_ip", debug_from_ip) )
		debug_from_ip = "";
	if( !cfg->getParam("debug_ip_file", debug_ip_file) )
		debug_ip_file = "";
	
	return;
}

void read_domains()
{
	// reading domain names file 'domains.txt'
	ifstream dfile;
	string dline;
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
	
	return;
}

void read_urls()
{
	ifstream ufile;
	string uline;
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
	return;
}

void print_options(void)
{
	printf("\n%s Version %s", PROG_NAME, PROG_VER);
	printf("\n\nSyntax: nfq <-c config_file> [ -h ] [ -d ]\n\n");
	printf("  -c\t\t- specify config file to read\n");
	printf("  -h\t\t- displays this help and exit.\n");
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

void *tread_conf_function( void *)
{
	printf("Thread: read config files...started\n");
	
	while( 1 ) {
//		sleep(1);
		sleep(1800);	// 30 mins.
		writelog("%s", " - Re-reading domains and urls files...\n");
		Mutex.lock();
			urls.clear();
			domains.clear();
			read_domains();
			read_urls();
		Mutex.unlock();
	}
	pthread_exit(NULL);
}



void *twrite_log_function( void *)
{
	printf("Thread: write log file...started\n");
	
	statm_t mem;
	char buf[128];
	
	while(1){
		sleep(120);
		read_mem(mem);
		writelog( "\n--- stats ---\nFiltered: %lu\nCaptured: %lu\nMemory: %ld\n\n", filtered, captured, mem.size);
	}
	pthread_exit(NULL);
}

void writelog( const char *fmt, ... ) {
        if( f_log == NULL ) {
                printf("Log file is not opened! Exiting.\n");
                exit(-1);
        }

        time_t now = time(0);
        struct tm tstruct;
        char b[80];
        tstruct = *localtime(&now);
        strftime(b, sizeof(b), "%d.%m.%Y %X", &tstruct );

        fprintf( f_log, "%s:\t", b );         // datetime

        va_list arg;
        va_start( arg, fmt );
		vfprintf( f_log, fmt, arg );
        va_end(arg);

        if( daemonized == 0 ) {
		va_start( arg, fmt );
		printf( "%s:", b );
		vprintf( fmt, arg );
		va_end(arg);
        }

        fflush( f_log );
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
		
		// Process only TCP proto:
		if( id_protocol == IPPROTO_TCP ) {
			char src_ip[32], dst_ip[32];
			strcpy( src_ip, get_src_ip_str(full_packet) );
			strcpy( dst_ip, get_dst_ip_str(full_packet) );
			
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
			
			char result[4096] = {0};
			getData( (unsigned char*)full_packet + sizeof(struct ip) + (4*tcph->doff), size - (tcph->doff*4) - sizeof(struct ip), result );
			std::string res = result;
			
			http_request r;
			if( !parse_http( res, &r ) ) {
				if( debug_ip == 1 && debug_from_ip == src_ip ) {
					fprintf( f_debug_ip, " - Packet captured: %s:%d -> %s:%d :: Header: %s", src_ip, get_tcp_src_port(full_packet), dst_ip, get_tcp_dst_port(full_packet), hdr );
					fprintf( f_debug_ip, "%s\nFull packet:\n%s", "parse_http() failed.", res.c_str() );
				}
				nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
				return(0);
			}  else {
				string host = r.host;
				string url = r.full_url;
				string method = r.method;
				string full_url = r.full_url;
				
				Mutex.lock();
				// Check in domain list
				if( domains.find( host ) != domains.end() ) {
					Mutex.unlock();
					if( debug > 0 )
						writelog(" - Packet filtered by DOMAIN: %s (%s) :: %s:%d -> %s:%d :: Header: %s", host.c_str(), full_url.c_str(), src_ip, get_tcp_src_port(full_packet), dst_ip, get_tcp_dst_port(full_packet), hdr );
					if( debug == 2 || debug == 4 )
						writelog("Full packet:\n%s", res.c_str() );
					
					if( debug_ip == 1 && debug_from_ip == src_ip ) {
						fprintf( f_debug_ip, " - Packet filtered by DOMAIN: %s (%s) :: %s:%d -> %s:%d :: Header: %s", host.c_str(), full_url.c_str(), src_ip, get_tcp_src_port(full_packet), dst_ip, get_tcp_dst_port(full_packet), hdr );
						fprintf( f_debug_ip, "Full packet:\n%s", res.c_str() );
					}
					
					Sender->Redirect( get_tcp_src_port(full_packet), get_tcp_dst_port(full_packet),
						 /*user ip*/src_ip, dst_ip,
						 /*acknum*/ tcph->ack_seq, /*seqnum*/ tcph->seq,
						 /* flag psh */ (tcph->psh ? 1 : 0 ) );
					filtered++;
					nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
					return(0);
				} else {
						// Get hash of this url
						unsigned long url_hash = djb2( (unsigned char*)full_url.c_str() );
						if( urls.find( url_hash ) != urls.end() ) {
							Mutex.unlock();
							if( debug > 0 )
								writelog(" - Packet filtered by URL: %s :: %s:%d -> %s:%d :: Header: %s", full_url.c_str(), src_ip, get_tcp_src_port(full_packet), dst_ip, get_tcp_dst_port(full_packet), hdr );
							if( debug == 2 || debug == 4 )
								writelog("Full packet:\n%s", res.c_str() );
							
							if( debug_ip == 1 && debug_from_ip == src_ip ) {
								fprintf(f_debug_ip, " - Packet filtered by URL: %s :: %s:%d -> %s:%d :: Header: %s", full_url.c_str(), src_ip, get_tcp_src_port(full_packet), dst_ip, get_tcp_dst_port(full_packet), hdr );
								fprintf(f_debug_ip, "Full packet:\n%s", res.c_str() );
							}
							
							Sender->Redirect( get_tcp_src_port(full_packet), get_tcp_dst_port(full_packet),
									src_ip, dst_ip, tcph->ack_seq, tcph->seq,
									(tcph->psh ? 1 : 0 ) );
							filtered++;
							nfq_set_verdict( qh, id, NF_DROP, 0, NULL);
							return(0);
						}
					Mutex.unlock();
				}
				
				if( debug_ip == 1 && debug_from_ip == src_ip ) {
					fprintf(f_debug_ip, "Packet NOT filtered: %s:%d -> %s:%d,\tHeader: %sHost: %s :: URL: %s\nFull packet:\n%s", src_ip, get_tcp_src_port(full_packet), dst_ip, get_tcp_dst_port(full_packet), hdr, host.c_str(), full_url.c_str(), res.c_str() );
				}
				
				// HTTP parsed, but packet not filtered:
				if( debug == 3 || debug == 4 )
					writelog("Packet NOT filtered: %s:%d -> %s:%d,\tHeader: %s\nHost: %s :: URL: %s\n", src_ip, get_tcp_src_port(full_packet), dst_ip, get_tcp_dst_port(full_packet), hdr, host.c_str(), full_url.c_str() );
				if( debug == 4 )
					writelog("Full packet:\n%s", res.c_str() );
			}
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
		writelog( "%s", (char *)"Cant open /proc/self/statm!\n");
		exit(-1);
	}
	
	if( 7 != fscanf(f,"%ld %ld %ld %ld %ld %ld %ld", &result.size,&result.resident,&result.share,&result.text,&result.lib,&result.data,&result.dt))
	{
		writelog("%s\n", "ERROR! Can't read mem!");
		perror(statm_path);
		return;
	}
//	writelog("\n---meminfo---\n%ld %ld %ld", result.size, result.share, result.data);
	
	fclose(f);
}

