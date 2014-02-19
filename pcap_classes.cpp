#include "pcap.h"
#include "pcap_classes.h"
#include "Checker.h"

// a WinPcap muködéséhez szükséges fejléc
#include <winsock.h>

using namespace System;
using namespace System::Text;
using namespace ARPWatch;

struct pcap { };	// VC .NET BUG WORKAROUND
// **********************************************************************************
// 4 byteból konstruál IPv4 címet
IPv4Address::IPv4Address(u_char* _address) {
	for (int i = 0 ; i < 4; i++) {
		address <<= 8;
		address += _address[i];
	}
}

// a .NET framework által használt függvény (pl. Hashtable-ben)
bool IPv4Address::Equals(Object* in) {
	try {
		return (__try_cast<IPv4Address*>(in))->address==address;
	} catch (Exception*) {
		return false;
	}
}

String *IPv4Address::ToString() {
	StringBuilder* ret = new StringBuilder(20);	// ebbe biztosan belefér, így biztosan nem lesz szükség átméretezésre

	for (int i = 3; i >= 1; i--) {
		ret->Append((unsigned char)(address>>(8*i)) & 0xff)->Append(".");
	}
	return ret->Append((unsigned char)(address & 0xff))->ToString();
}

String* IPv4Address::SerializeText() {
	return ToString();
}

// sztringbol konstruál egy IPv4 címet
IPv4Address::IPv4Address(String* in) {
	int val = 0;
	address = 0;
	int dotnum = 0;

	for (int i = 0; i < in->Length; i++) {
		if ((in->Chars[i] >= '0') && (in->Chars[i] <= '9')) {
			val *= 10;
			val += in->Chars[i] - '0';
		} else if (in->Chars[i] == '.') {
			address <<= 8;
			address += val;
			dotnum++;
			val = 0;
		} else if (dotnum < 3) {
			throw new ApplicationException((new StringBuilder(S"IPv4Address format error: "))->Append(in)->ToString());
		} else break;	// IP-cim vege
	}
	address <<= 8;
	address += val;
}

Object* IPv4Address::DeSerializeText(String* in) {
	return new IPv4Address(in);
}

// **********************************************************************************
EthernetAddress::EthernetAddress(u_char* _address) {
	for (int i = 0 ; i < 6; i++) {
		address <<= 8;
		address += _address[i];
	}
}

bool EthernetAddress::Equals(Object* in) {
	try {
		return (__try_cast<EthernetAddress*>(in))->address==address;
	} catch (Exception*) {
		return false;
	}
}

String *EthernetAddress::ToString() {
	StringBuilder* ret = new StringBuilder(25);

	for (int i = 40; i > 0; i-=8) {
		ret->AppendFormat(S"{0:x02}:", __box((address>>i)&0xff));
	}
	return ret->AppendFormat(S"{0:x02}", __box(address&0xff))->ToString();
}

String* EthernetAddress::SerializeText() {
	return ToString();
}

EthernetAddress::EthernetAddress(String *in) {
	address = 0;
	int p = 0;
	for (int i = 0 ; i < 6; i++) {
		int val = 0;

		if (in->Chars[p] > '9') val = (in->Chars[p]-'a'+10)<<4;
		else val = (in->Chars[p]-'0')<<4;
		p++;
		if (in->Chars[p] > '9') val += in->Chars[p]-'a'+10;
		else val += in->Chars[p]-'0';
		p+=2;	// Átugorjuk a : -ot is

		address <<= 8;
		address += val;
	}
}

Object* EthernetAddress::DeSerializeText(String* in) {
	return new EthernetAddress(in);
}

// **********************************************************************************
void PacketInfo::crop(int header, int footer) {
	if (header + footer >= retLen)
		throw new ApplicationException(S"Attempted to set length below 0");

	retLen -= header+footer;
	retData += header;
}

String *PacketInfo::ToString() {
	return S"PacketInfo::ToString() not implemented yet";
}

// **********************************************************************************
String *Packet::ToString() {
	StringBuilder *ret = new StringBuilder();
	
	for (int i = 0; i < pi->Length; i++) {
		ret->AppendFormat("{0:x2} ", __box(pi->Data[i]));
		if ((i+1)%16 == 0) ret->Append("\n");
	}
	return ret->ToString();
}

CheckResult* Packet::accept(Checker* checker, CheckResult* in) {
	return checker->visitPacket(this, in);
}

Packet* Packet::createPacket(PacketInfo* in) {
	// Ha van gyerekünk, végigmegyünk rajtuk, és rekurzívan hívogatjuk
	// oket addig, amíg nem NULLt kapunk vissza, vagyis amíg 
	// valamelyik gyerek valahanyadik ose felismerte magát
	Packet* ret;
	for (int i = 0; i < child->Length; i++) {
		if (ret = child[i]->createPacket(in)) return ret;
	}

	// ha nincs gyerekünk, vagy egyikük sem ismeri fel a csomagot,
	// akkor miénk a csomag kezelésének feladata
	return createInstance(in);
}

void Packet::addChild(Packet *p) {
	// a minden regisztrációt követo child tömb-újrapéldányosítás gyorsabb futást eredményez
	int childLen = child->Length;
	Packet *newchild __gc[] = new Packet * __gc[childLen+1];
	Array::Copy(child, newchild, childLen);
	newchild[childLen] = p;
	child = newchild;
}

// **********************************************************************************
EthernetPacket::EthernetPacket(PacketInfo *in) : Packet(in) {
	dst = new EthernetAddress(&(pi->Data[0]));
	src = new EthernetAddress(&(pi->Data[6]));
	type = (pi->Data[12]<<8)+pi->Data[13];
	pi->crop(14, 0);
}

String *EthernetPacket::ToString() {
	StringBuilder *ret = new StringBuilder();
	
	ret->Append(S"EthernetPacket");
	ret->Append(S" SRC=")->Append(src);
	ret->Append(S" DST=")->Append(dst);
	ret->Append(S" TYPE=")->AppendFormat(S"{0:X04}", __box(type));
	ret->Append(S" LEN=")->AppendFormat(S"{0}", __box(pi->Length));
	return ret->ToString();
}

CheckResult* EthernetPacket::accept(Checker* checker, CheckResult* in) {
	CheckResult* ret = checker->visitEthernetPacket(this, in);
	return __super::accept(checker, ret);
}

// **********************************************************************************
ARPPacket::ARPPacket(PacketInfo *in) : EthernetPacket(in) {
	htype = (pi->Data[0]<<8)+pi->Data[1];
	ptype = (pi->Data[2]<<8)+pi->Data[3];
	hlen = pi->Data[4];
	plen = pi->Data[5];
	operation = (pi->Data[6]<<8)+pi->Data[7];
	src_eth = new EthernetAddress(&(pi->Data[8]));
	src_ip = new IPv4Address(&(pi->Data[14]));
	dest_eth = new EthernetAddress(&(pi->Data[18]));
	dest_ip = new IPv4Address(&(pi->Data[24]));

	// reseteljuk, hatha valakinek meg szuksege lesz a PacketInfo-ra
	// ennek a protokollnak mar nem lesz gyereke
	pi->reset();
}

String *ARPPacket::ToString() {
	StringBuilder *ret = new StringBuilder();
	
	switch (operation) {
		case ARPPacket::OP_REQUEST:
			ret->Append(S"ARP request"); break;
		case ARPPacket::OP_REPLY:
			ret->Append(S"ARP reply"); break;
		case ARPPacket::OP_RREQUEST:
			ret->Append(S"RARP request"); break;
		case ARPPacket::OP_RREPLY:
			ret->Append(S"RARP reply"); break;
		default:
			ret->Append(S"ARP unknown"); break;
	}
	ret->Append(S" SRCETH=")->Append(src_eth->ToString())->Append(S" SRCIP=")->Append(src_ip->ToString());
	ret->Append(S" DSTETH=")->Append(dest_eth->ToString())->Append(S" DSTIP=")->Append(dest_ip->ToString());
	return ret->ToString();
}

Packet* ARPPacket::createPacket(PacketInfo* in) {
	// az ethernet csomag 12. és 13. byte-ja a típus
	int type = (in->Data[12]<<8)+in->Data[13];
	// 0x806 az ARP csomag azonosítója
	if (type != 0x806) return NULL;

	// Az ethernet csomag 14-18. byteja a hardver es a protokoll cim azonosito
	int htype = (in->Data[14]<<8)+in->Data[15];
	int ptype = (in->Data[16]<<8)+in->Data[17];
	// a hardware cimnek csak ethernet-et, a protokoll cimnek pedig csak IPv4-et fogadunk el
	if ((htype != 0x0001) || (ptype != 0x0800)) return NULL;

	// megfelelo ARP csomagot kaptunk, folytatódhat a feldolgozás
	return Packet::createPacket(in);
}

CheckResult* ARPPacket::accept(Checker* checker, CheckResult* in) {
	CheckResult* ret = checker->visitARPPacket(this, in);
	return __super::accept(checker, ret);
}

// **********************************************************************************
IPv4Packet::IPv4Packet(PacketInfo *in) : EthernetPacket(in) {
	version = (in->Data[0] & 0xf0) >> 4;
	hlen = (in->Data[0] & 0x0f) * 4;
	pid = in->Data[9];
	src_ip = new IPv4Address(&(pi->Data[12]));
	dst_ip = new IPv4Address(&(pi->Data[16]));

	pi->crop(hlen, 0);
}

String *IPv4Packet::ToString() {
	StringBuilder *ret = new StringBuilder();
	
	ret->Append(S"IPPacket ");
	ret->Append(S" SRCIP=")->Append(src_ip->ToString());
	ret->Append(S" DSTIP=")->Append(dst_ip->ToString());
	return ret->ToString();
}

Packet* IPv4Packet::createPacket(PacketInfo* in) {
	// az ethernet csomag 12. és 13. byte-ja a típus
	int type = (in->Data[12]<<8)+in->Data[13];
	// 0x800 az IP csomag azonosítója
	if (type != 0x800) return NULL;

	// megfelelo IP csomagot kaptunk, folytatódhat a feldolgozás
	return Packet::createPacket(in);
}

CheckResult* IPv4Packet::accept(Checker* checker, CheckResult* in) {
	CheckResult* ret = checker->visitIPv4Packet(this, in);
	return __super::accept(checker, ret);
}

// **********************************************************************************
UDPPacket::UDPPacket(PacketInfo *in) : IPv4Packet(in) {
	src_port = (pi->Data[0]<<8)+pi->Data[1];
	dst_port = (pi->Data[2]<<8)+pi->Data[3];
	pi->crop(8, 0);
}

String *UDPPacket::ToString() {
	StringBuilder *ret = new StringBuilder();
	
	ret->Append(S"UDPPacket ");
	ret->Append(S" SRC=")->Append(src_ip->ToString())->Append(S":")->Append(src_port);
	ret->Append(S" DST=")->Append(dst_ip->ToString())->Append(S":")->Append(dst_port);
	return ret->ToString();
}

Packet* UDPPacket::createPacket(PacketInfo* in) {
	// az ethernet csomag 23. byte-ja az IP protokollja
	int type = in->Data[23];
	// 0x11 az UDP csomag azonosítója
	if (type != 0x11) return NULL;

	// megfelelo IP csomagot kaptunk, folytatódhat a feldolgozás
	return Packet::createPacket(in);
}

CheckResult* UDPPacket::accept(Checker* checker, CheckResult* in) {
	CheckResult* ret = checker->visitUDPPacket(this, in);
	return __super::accept(checker, ret);
}

// **********************************************************************************
DHCPPacket::DHCPPacket(PacketInfo *in) : UDPPacket(in) {
	type = pi->Data[0];
	htype = pi->Data[1];
	hlen = pi->Data[2];
	
	client_ip = new IPv4Address(&(pi->Data[16]));
	client_eth = new EthernetAddress(&(pi->Data[28]));

	// reseteljuk, hatha valakinek meg szuksege lesz a PacketInfo-ra
	// ennek a protokollnak mar nem lesz gyereke
	pi->reset();
}

String *DHCPPacket::ToString() {
	StringBuilder *ret = new StringBuilder();
	
	switch (type) {
		case DHCPPacket::DHCP_REQUEST:
			ret->Append(S"DHCP request"); break;
		case DHCPPacket::DHCP_REPLY:
			ret->Append(S"DHCP reply"); break;
		default:
			ret->Append(S"DHCP unknown"); break;
	}
	ret->Append(S" ClientETH=")->Append(client_eth->ToString())->Append(" ClientIP=")->Append(client_ip->ToString());

	return ret->ToString();
}

Packet* DHCPPacket::createPacket(PacketInfo* in) {
	// az ethernet csomag 14-es byte-jának alsó 4 bitjének négyszerese az IP csomag fejlecenek hossza byte-ban
	int iplen = (in->Data[14] & 0x0f) * 4;

	// megallapitjuk az UDP portok szamait
	int udpdstport = (in->Data[14+iplen+2]<<8)+in->Data[14+iplen+3];
	// ha nem a bootp szerver vagy a bootp kliens portjara iranyult
	// az UDP forgalom, figyelmen kivul hagyjuk
	if (udpdstport != 67 && udpdstport != 68) return NULL;

	// megfelelo DHCP csomagot kaptunk, folytatódhat a feldolgozás
	return Packet::createPacket(in);
}

CheckResult* DHCPPacket::accept(Checker* checker, CheckResult* in) {
	CheckResult* ret = checker->visitDHCPPacket(this, in);
	return __super::accept(checker, ret);
}

// **********************************************************************************
Adapter::Adapter(pcap_if *_adapter) {
	adapter = _adapter;
	adhandle = NULL;
	ipaddr = NULL;

	// IP-cim kideritese
	for (pcap_addr* i = adapter->addresses; i; i = i->next) {
		if (i->addr->sa_family == AF_INET) {
			u_long baa = ntohl(((struct sockaddr_in *)i->addr)->sin_addr.s_addr);
			ipaddr = new IPv4Address(baa);
		}
	}
}

bool Adapter::isLoopback() {
	return adapter->flags & PCAP_IF_LOOPBACK;
}

void Adapter::open(int caplen) {
	char errbuf[PCAP_ERRBUF_SIZE];

	adhandle = pcap_open_live(adapter->name, caplen, 1, 1000, errbuf);

	if (adhandle == NULL)
		throw new ApplicationException((new StringBuilder("Error in pcap_open: "))->Append(errbuf)->ToString());
}

void Adapter::close() {
	if (adhandle == NULL)
		throw new ApplicationException("Adapter already closed");

	pcap_close(adhandle);
	adhandle = NULL;
}

Packet *Adapter::read() {
	if (adhandle == NULL)
		throw new ApplicationException("Adapter is not open");

	int res;
	struct pcap_pkthdr *header;
	u_char *pkt_data;

	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
		if (res == 0)	//timeout
			continue;

		// timestamp konverzió
		DateTime ts(1970, 1, 1);
		ts = ts.AddSeconds(header->ts.tv_sec);
		ts = ts.AddMilliseconds(header->ts.tv_usec/1000);
		PacketInfo *pi = new PacketInfo(header->caplen, pkt_data, ts, this);
		return PacketFactory::createPacket(pi);
	}
	
	throw new ApplicationException((new StringBuilder("An error occured: "))->Append(pcap_geterr(adhandle))->ToString());
	// VC.NET BUG
	//return NULL;
}

void Adapter::setFilter(char *filter) {
	if (adhandle == NULL) {
		throw new ApplicationException("Adapter is not open");
	}

	u_int netmask;
	if (adapter->addresses) {
		netmask = ntohl(((sockaddr_in *)(adapter->addresses->netmask))->sin_addr.s_addr);
	} else {
		// feltesszük, hogy egy C osztályú alhálózaton vagyunk
		netmask = 0xffffff;
	}

	bpf_program fcode;

	if (pcap_compile(adhandle, &fcode, filter, 1, netmask) < 0) {
		throw new ApplicationException((new StringBuilder("Error while compiling filter code: "))->Append(pcap_geterr(adhandle))->ToString());
	}

	if (pcap_setfilter(adhandle, &fcode) <0 ) {
		throw new ApplicationException((new StringBuilder("Error while setting filter: "))->Append(pcap_geterr(adhandle))->ToString());
	}
}

String *Adapter::ToString() {
	return new String(adapter->description);
}

// **********************************************************************************
// azert global, mert igy biztosan nem managed tipusu, igy kulso fuggvenyek is elerik
pcap_if *alldevs;

AdapterManager::AdapterManager() {
	pcap_if *d;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    /* Retrieve the device list */
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		throw new ApplicationException((new StringBuilder("Error in pcap_findalldevs: "))->Append(errbuf)->ToString());
    }

	adapter = new ArrayList(10);
	for (d = alldevs; d; d=d->next) {
		Adapter *actad = new Adapter(d);
		adapter->Add(actad);
	}
		
	if (adapter->Count < 1)
		throw new ApplicationException("No adapters found");
}

AdapterManager::~AdapterManager() {
	pcap_freealldevs(alldevs);
}

Adapter* AdapterManager::getAdapter(int which) {
	return static_cast<Adapter*>(adapter->Item[which]);
}
