/**
 * g++ traceroute.cpp && sudo ./a.out <your url> <optional: your ip>
 * eg. `g++ traceroute.cpp && sudo ./a.out nus.edu.sg 123.123.123.123`
 **/

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <algorithm>
#include <iostream>
#include <string>
#include <utility>

#define PCKT_LEN 1000
#define TIMEOUT 3
#define QUERY_PER_HOP 3
#define HOP_COUNT 30

#define DEBUG 0

struct pseudo_header {
  u_int32_t source_address;
  u_int32_t dest_address;
  u_int8_t placeholder;
  u_int8_t protocol;
  u_int16_t tcp_length;
};

// Retrieve the URL's IP address.
static std::string GetIPAddr(const std::string &url) {
  addrinfo hints, *infoptr;
  hints.ai_family = AF_INET; // AF_INET means IPv4 only addresses

  int result = getaddrinfo(url.c_str(), "https", nullptr, &infoptr);
  if (result) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(result));
    exit(1);
  }

  addrinfo *p;
  char host[256];

  for (p = infoptr; p != NULL; p = p->ai_next) {
    getnameinfo(p->ai_addr, p->ai_addrlen, host, sizeof(host), NULL, 0,
                NI_NUMERICHOST);
    // We only get 1 ip addr
    break;
  }

  freeaddrinfo(infoptr);
  return std::string(host);
}

sockaddr_in CreateSockAddr(int port, std::string uri = "") {
  struct sockaddr_in sin;
  sin.sin_family = AF_INET;
  sin.sin_port = htons(port);
  if (!uri.empty()) {
    sin.sin_addr.s_addr = inet_addr(GetIPAddr(uri).c_str());
  }

  return sin;
}

int CreateSock(int protocol, bool isRaw) {
  int sock = 0;
  int inet = protocol == IPPROTO_TCP ? AF_INET : PF_INET;
  if ((sock = socket(inet, SOCK_RAW, protocol)) < 0) {
    perror("Socket creation error");
    exit(1);
  }
  int one = 1;
  const int *val = &one;
  if (isRaw) {
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
      perror("Error setting IP_HDRINCL");
      exit(0);
    }
  }

  struct timeval tv;
  tv.tv_sec = TIMEOUT;
  tv.tv_usec = 0;
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);
  return sock;
}

// Leeched from:
// https://gist.github.com/yorickdewid/a6e4f7181bfcb6aad5cc#file-synflood-c-L51
unsigned short csum(unsigned short *ptr, int nbytes) {
  register long sum;
  unsigned short oddbyte;
  register short answer;

  sum = 0;
  while (nbytes > 1) {
    sum += *ptr++;
    nbytes -= 2;
  }
  if (nbytes == 1) {
    oddbyte = 0;
    *((u_char *)&oddbyte) = *(u_char *)ptr;
    sum += oddbyte;
  }

  sum = (sum >> 16) + (sum & 0xffff);
  sum = sum + (sum >> 16);
  answer = (short)~sum;

  return (answer);
}

ip *generateIPDatagram(char *buffer, const std::string &destIP, int ttl) {
  class ip *iph = (struct ip *)buffer;

  iph->ip_hl = 5;
  iph->ip_v = 4;
  iph->ip_tos = rand();
  iph->ip_id = htons(rand() % 65535);
  iph->ip_ttl = ttl;
  iph->ip_p = IPPROTO_TCP;
  iph->ip_len = sizeof(ip) + sizeof(tcphdr);
  inet_pton(AF_INET, destIP.c_str(), &(iph->ip_dst));
  iph->ip_sum = csum((unsigned short *)buffer, iph->ip_len);

  memcpy(buffer, iph, sizeof(struct ip));
  return iph;
}

void generateTCPHeader(char *buffer, int dest_port, int src_port,
                       sockaddr_in &sin, const std::string& localIp) {
  struct tcphdr *tcph = (tcphdr *)(buffer + sizeof(struct ip));

  // The TCP structure
  tcph->th_dport = htons(dest_port);
  tcph->th_sport = htons(src_port);
  tcph->th_off = 5;
  tcph->th_flags = TH_SYN;
  tcph->th_seq = htonl(rand());
  tcph->th_ack = 0;
  tcph->th_win = htons(500);

  char *pseudogram;
  struct pseudo_header psh;

  if (!localIp.empty()) {
    psh.source_address = inet_addr(localIp.c_str());
  }
  psh.dest_address = sin.sin_addr.s_addr;
  psh.placeholder = 0;
  psh.protocol = IPPROTO_TCP;
  psh.tcp_length = htons(sizeof(struct tcphdr));

  int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
  pseudogram = (char *)malloc(psize);

  memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
  memcpy(pseudogram + sizeof(struct pseudo_header), tcph,
         sizeof(struct tcphdr));

  tcph->th_sum = csum((unsigned short *)pseudogram, psize);
  memcpy(buffer + sizeof(struct ip), tcph, sizeof(struct tcphdr));
  return;
}

unsigned short SendTcpSynPacket(int sock, int ttl, const std::string &URI,
                                sockaddr_in &sin, int src_port, int dest_port, const std::string& localIP) {
  char *buffer = new char[PCKT_LEN]();
  ip *iph = generateIPDatagram(buffer, GetIPAddr(URI), ttl);
  generateTCPHeader(buffer, dest_port, src_port, sin, localIP);
  if (sendto(sock, buffer, iph->ip_len, 0, (struct sockaddr *)&sin,
             sizeof(sin)) < 0) {
    perror("sendto failed");
    return 0;
  }
  return ntohs(iph->ip_id);
}

/**
 * @return {icmp matches ip_id, port_unreachable}
 **/
std::pair<bool, bool> getIcmpPacket(const char *reply, const sockaddr_in &sin,
                                    unsigned short ip_id) {
  int hlen = sizeof(struct ip);
  struct icmp *icp = (struct icmp *)(reply + hlen);
  // TODO(weineng): Implement termination when we reach IP.

  struct ip *icmp_iph = (struct ip *)(reply + hlen + sizeof(icp));
  struct ip *ip_reply = (struct ip *)reply;

  if (ip_id != ntohs(icmp_iph->ip_id)) {
    DEBUG &&std::cout << "WE RECEIVED GARBAGE: "
                      << "(" << ntohs(icmp_iph->ip_id) << ", " << ip_id << ")";
    return {false, false};
  }
  if (ip_reply->ip_p == 1) {
    std::cout << inet_ntoa(sin.sin_addr);
  }

  DEBUG &&std::cout << "  ICMP: (" << (int)icp->icmp_type << ", "
                    << (int)icp->icmp_code << ")";
  if (icp->icmp_type == ICMP_UNREACH && icp->icmp_code == ICMP_UNREACH_PORT) {
    return {true, true};
  }
  return {true, false};
}

bool IsResultInSock(int sock) {
  fd_set rfds;
  FD_ZERO(&rfds);
  FD_SET(sock, &rfds);

  struct timeval tv;
  tv.tv_sec = TIMEOUT;
  tv.tv_usec = 0;

  int retval = select(sock + 1, &rfds, NULL, NULL, &tv);
  return retval != -1;
}

char *ReadSocket(int sock, sockaddr_in &sin) {
  char *recv_buffer = new char[PCKT_LEN]();
  memset(recv_buffer, 0, PCKT_LEN);
  socklen_t addrlen = sizeof(sin);
  if (!IsResultInSock(sock) ||
      recvfrom(sock, recv_buffer, PCKT_LEN, 0, (struct sockaddr *)&sin,
               &addrlen) == -1) {
    return nullptr;
  }
  return recv_buffer;
}

/**
 * Create a socket and from the specified port. Retry method if fail, up to
 *`tries` times.
 **/
bool ReadFromICMP(int port, unsigned short ip_id) {
  struct sockaddr_in recv_addr = CreateSockAddr(port);
  int sock = CreateSock(IPPROTO_ICMP, true);

  for (int i = 0; i < QUERY_PER_HOP; ++i) {
    char *recv_buffer = ReadSocket(sock, recv_addr);
    if (recv_buffer != nullptr) {
      auto result = getIcmpPacket(recv_buffer, recv_addr, ip_id);
      if (/* port unreachable */ std::get<1>(result)) {
        close(sock);
        return true;
      }
      if (/* zero_ttl_icmp */ std::get<0>(result)) {
        break;
      }
    }
    std::cout << "* ";
    std::cout.flush();
  }
  close(sock);
  return false;
}

bool isRstTcpPacket(char *buffer) {
  if (buffer == nullptr) {
    return false;
  }
  int hlen = sizeof(struct ip);
  struct tcphdr *tcph = (struct tcphdr *)(buffer + hlen);
  return tcph->th_flags == TH_RST;
}

void PrintConfig(int dest_port, const std::string &ip, const std::string &url) {
  std::cout << "---------- CONFIG ----------" << std::endl;
  std::cout << "Selection option are to wait for " << TIMEOUT << " seconds."
            << std::endl;
  std::cout << QUERY_PER_HOP << " queries are sent in each hop." << std::endl;
  ;
  std::cout << "Up to " << HOP_COUNT
            << " hops are performed before program terminates" << std::endl;
  std::cout << "Host to trace: " << url << " (" << ip << ""
            << ":" << dest_port << ")" << std::endl;
  std::cout << std::endl;
}

int main(int argc, char *argv[]) {
  if (argc != 2 && argc != 3) {
    std::cout << "usage: faketraceroute <URL> <optional: your ip>"
              << std::endl;
    std::cout << "eg: faketraceroute facebook.com 10.0.0.1"
              << std::endl;
    return 1;
  }
  srand(time(NULL));
  std::string URI = argv[1];
  std::string localIP = argc == 3 ? argv[2] : "";
  u_int16_t DEST_PORT = rand() % 50000 + 4000;

  PrintConfig(DEST_PORT, GetIPAddr(URI), URI);

  for (int ttl = 1; ttl <= HOP_COUNT; ++ttl) {

    int send_sock = CreateSock(IPPROTO_TCP, true);
    struct sockaddr_in sin = CreateSockAddr(DEST_PORT, URI);
    u_int16_t SRC_PORT = rand() % 50000 + 4000;

    std::cout << ttl << ". ";
    std::cout.flush();
    unsigned short ip_id =
        SendTcpSynPacket(send_sock, ttl, URI, sin, SRC_PORT, DEST_PORT, localIP);

    // TODO(wn) try to read RST.
    //   int tcp_recv_sock = CreateSock(IPPROTO_TCP, false);
    //   // char* recv_buffer = ReadSocket(tcp_recv_sock, sin2);

    //   char *recv_buffer = new char[PCKT_LEN]();
    //   memset(recv_buffer, 0, PCKT_LEN);
    // //     if (connect(tcp_recv_sock, (struct sockaddr *)&sin2, sizeof(sin2))
    // < 0) {
    // //   printf("\nConnection Failed \n");
    // //   return -1;
    // // }

    //     socklen_t addrlen = sizeof(sin);
    //     if (//!IsResultInSock(tcp_recv_sock) ||
    //        recvfrom(tcp_recv_sock, recv_buffer, PCKT_LEN, 0, (struct sockaddr
    //        *)&sin,
    //                  &addrlen) != -1) {
    //   if (isRstTcpPacket(recv_buffer)) {
    //         std::cout << "fffff"<< std::endl;
    //     } else {
    //       std::cout << "ggg"<< std::endl;
    //     }
    //   }
    close(send_sock);

    int dest_found = ReadFromICMP(SRC_PORT, ip_id);
    std::cout << std::endl;
    if (dest_found) {
      std::cout << "port unreachable" << std::endl;
      return 0;
    }
  }
  std::cout << "Time Out" << std::endl;
  return 1;
}
