#ifndef STRUCT
#define STRUCT
/* IP header */
#include <winsock2.h>
#include <Windows.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdint.h>
#include "mstcpip.h"


#define MAX_ADAPTER_NAME_LENGTH 256
#define MAX_ADAPTER_DESCRIPTION_LENGTH 128
#define MAX_ADAPTER_ADDRESS_LENGTH 8
#define UDP_HEADER 8
#pragma pack(1)
struct ip_pkt
{
	unsigned char vhl;		/* version << 4 | header length >> 2 */
	unsigned char tos;		/* type of service */
	unsigned short len;		/* total length */
	unsigned short id;		/* identification */
	unsigned short offset;	/* fragment offset field */
	unsigned char ttl;		/* time to live */
	unsigned char pro;		/* protocol */
	unsigned short cksum;	/* checksum */
	in_addr src, dst;		/* source and dest address */
};
#define IP_V(ip)		(((ip)->vhl) >> 4)
#define IP_HL(ip)		(((ip)->vhl) & 0x0f)

struct et_header
{
	unsigned char   eh_dst[6];
	unsigned char   eh_src[6];
	unsigned short  eh_type;
};
struct psd_header{
	ULONG  sourceip;    //ԴIP��ַ
	ULONG  destip;      //Ŀ��IP��ַ
	BYTE mbz;           //�ÿ�(0)
	BYTE ptcl;          //Э������
	USHORT plen;        //TCP/UDP���ݰ��ĳ���(����TCP/UDP��ͷ�������ݰ������ĳ��� ��λ:�ֽ�)
};

struct tcp_Header {
	USHORT srcport;   // Դ�˿�
	USHORT dstport;   // Ŀ�Ķ˿�
	UINT seqnum;      // ˳���
	UINT acknum;      // ȷ�Ϻ�
	BYTE dataoff;     // TCPͷ��
	BYTE flags;       // ��־��URG��ACK�ȣ�
	USHORT window;    // ���ڴ�С
	USHORT chksum;    // У���
	USHORT urgptr;    // ����ָ��
};
//Necessary Structs
typedef struct
{
	char String[4 * 4];
} IP_ADDRESS_STRING, *PIP_ADDRESS_STRING, IP_MASK_STRING, *PIP_MASK_STRING;

typedef struct _IP_ADDR_STRING
{
	struct _IP_ADDR_STRING* Next;
	IP_ADDRESS_STRING IpAddress;
	IP_MASK_STRING IpMask;
	DWORD Context;
} IP_ADDR_STRING, *PIP_ADDR_STRING;

typedef struct _IP_ADAPTER_INFO
{
	struct _IP_ADAPTER_INFO* Next;
	DWORD           ComboIndex;
	char            AdapterName[MAX_ADAPTER_NAME_LENGTH + 4];
	char            Description[MAX_ADAPTER_DESCRIPTION_LENGTH + 4];
	UINT            AddressLength;
	BYTE            Address[MAX_ADAPTER_ADDRESS_LENGTH];
	DWORD           Index;
	UINT            Type;
	UINT            DhcpEnabled;
	PIP_ADDR_STRING CurrentIpAddress;
	IP_ADDR_STRING  IpAddressList;
	IP_ADDR_STRING  GatewayList;
	IP_ADDR_STRING  DhcpServer;
	BOOL            HaveWins;
	IP_ADDR_STRING  PrimaryWinsServer;
	IP_ADDR_STRING  SecondaryWinsServer;
	time_t          LeaseObtained;
	time_t          LeaseExpires;
} IP_ADAPTER_INFO, *PIP_ADAPTER_INFO;



struct icmp_hdr
{
	unsigned char icmp_type;   //����
	unsigned char code;        //����
	unsigned short chk_sum;    //16λ�����
};


//UDP��ͷ�ṹ
typedef struct _UDP{
	USHORT SrcPort; // Դ�˿�
	USHORT DstPort; // Ŀ�Ķ˿�
	USHORT Len; // ���ĳ���
	USHORT Chksum; // У���
}UDP_Header;


/*DNS���ݱ�ͷ*/
typedef struct dns_header
{
	USHORT id; //��ʶ��ͨ�����ͻ��˿��Խ�DNS��������Ӧ����ƥ�䣻
	USHORT flags; //��־����ѯ0x0100 Ӧ��:0x8180
	USHORT questions; //������Ŀ
	USHORT answers; //��Դ��¼��Ŀ
	USHORT author; //��Ȩ��Դ��¼��Ŀ
	USHORT addition; //������Դ��¼��Ŀ
}DNS_HEADER;


struct answer
{	
	unsigned short partion;
	unsigned short type;
	unsigned short class_in;
	unsigned int ttl;
	unsigned short data_len;
	in_addr ip_addr;
};


//Pointers to resource record contents


//Structure of a Query
typedef struct
{
	unsigned char *name;
	struct QUESTION *ques;
} QUERY;
#endif