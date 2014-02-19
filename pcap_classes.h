#pragma once

#include "pcap.h"
//#include "Checker.h"
// VC.NET BUG workaround: a windows.h -ban definialt makro .net framework alatt csak zavaro
#undef MessageBox

using namespace System;
using namespace System::Collections;

namespace ARPWatch {

// predefinici� a Checker-hez
public __gc class Checker;

// a sz�rializ�ci�hoz haszn�lt interf�sz
public __gc __interface KnowledgeBaseItemSerializer {
	String* SerializeText();
	Object* DeSerializeText(String* in);
};

// **********************************************************************************
// Kihaszn�ljuk, hogy az IPv4 c�m belef�r az unsigned long -ba, ami j�val hat�konyabb egy __gc[] -n�l
public __gc class IPv4Address : public KnowledgeBaseItemSerializer {
public:
	IPv4Address(u_long _address) {address = _address;};
	IPv4Address(String* in);
	IPv4Address(u_char* _address);

	String *ToString();
	// hash-k�nt az ip c�met adja vissza, mert pont j�
	int GetHashCode() {return address;};
	bool Equals(Object* in);
	// igaz, ha null- vagy broadcast c�m
	bool isSpecial() {return address==0 || address==0xffffffff;};

	String* SerializeText();
	Object* DeSerializeText(String* in);

protected:
	u_long address;
};

// **********************************************************************************
// Kihaszn�ljuk, hogy az ethernet c�m belef�r az __int64 -be, ami j�val hat�konyabb egy __gc[] -n�l
public __gc class EthernetAddress : public KnowledgeBaseItemSerializer {
public:
	EthernetAddress(u_char* _address);
	EthernetAddress(__int64 _address) {address = _address;};
	EthernetAddress(String* in);
	
	String *ToString();
	int GetHashCode() {return (int)((address&0xffffff) ^ (address>>24));};
	bool Equals(Object* in);
	// igaz, ha null- vagy broadcast c�m
	bool isSpecial() {return address==0 || address==0xffffffffffff;};

	String* SerializeText();
	Object* DeSerializeText(String* in);

protected:
	unsigned __int64 address;
};

// **********************************************************************************
// predefinicio
public __gc class Adapter;

// A nyers adatcsomaggal kapcsolatos informaciokat tarolja
public __gc class PacketInfo {
public:
	PacketInfo(int _len, u_char *_data, DateTime dt, Adapter* _captureAdapter) {
		len = retLen = _len;
		data = retData = _data;
		timeStamp = dt;
		captureAdapter = _captureAdapter;
	};

	// A csomag elej�bol �s v�g�bol nyes le
	void crop(int header, int footer);
	// vissza�ll�tja az eredeti, nyesetlen �llapotot
	void reset() {retLen = len; retData = data;};

	// a csomag val�di hossza
	__property int get_RealLength() {return len;};
	// a csomag val�di tartalma
	__property u_char *get_RealData() {return data;};
	// a csomag nyesett hossza
	__property int get_Length() {return retLen;};
	// a csomag nyesett tartalma
	__property u_char *get_Data() {return retData;};
	// az elfog�s idob�lyege
	__property DateTime get_TimeStamp() {return timeStamp;};
	// az elfog�st v�gzo adapter
	__property Adapter* get_CaptureAdapter() {return captureAdapter;};

	String *ToString();

protected:
	u_char *data, *retData;
	int len, retLen;
	DateTime timeStamp;
	Adapter* captureAdapter;
};

// **********************************************************************************
// az ellenorz�s eredm�nyeit t�rol� oszt�ly
public __gc class CheckResult {
private:
	ArrayList* warnings;

public:
	CheckResult() {warnings = new ArrayList();};

	// �j figyelmeztet�s megad�sa
	void addWarning(String* warn) {warnings->Add(warn);};

	// figyelmeztet�sek sz�m�nak lek�rdez�se
	__property int get_Count() {return warnings->Count;};
	// a megadott sorsz�m� figyelmeztet�s lek�rdez�se
	__property String* get_Warning(int i) {return static_cast<String*>(warnings->Item[i]);};
};

// **********************************************************************************
// Minden Packet oszt�ly ose
public __gc class Packet {
public:
	Packet() {child = new Packet* [0];};
	Packet(PacketInfo *in) : pi(in) {pi->reset();};

	// az elfog�s ideje
	__property DateTime get_TimeStamp() {return pi->TimeStamp;};
	// az elfog� adapter
	__property Adapter* get_CaptureAdapter() {return pi->CaptureAdapter;};

	// Megpr�b�lja feldolgozni a csomagot. Visszat�r�si �rt�ke NULL, ha ez sikertelen
	virtual Packet* createPacket(PacketInfo* in);
	// �j gyerek megad�sa a csomag-f�ban
	void addChild(Packet* p);

	virtual String* ToString();
	// a csomag kereszt�lfuttat�sa a megadott ellenorzon
	virtual CheckResult* accept(Checker* checker, CheckResult* in);

protected:
	// Ha nem virtual, akkor mindig az os-osztalybelit hivna meg a createPacket();
	virtual Packet* createInstance(PacketInfo *in) {return new Packet(in);};
	// A hierarchia fel�p�t�s�re szolg�l
	Packet* child __gc[];

	PacketInfo *pi;
};

// **********************************************************************************
// Az ethernetcsomag oszt�ly. Annyival t�bb a nyers csomagn�l, hogy �rtelmezi az ethernet csomag
// fejl�c�t, benne a k�ldo �s a c�mzett ethernet c�m�vel
public __gc class EthernetPacket : public Packet {
public:
	EthernetPacket() : Packet() {};
	EthernetPacket(PacketInfo *in);

	// a forr�s ethernet c�me (ethernet headerbol)
	__property EthernetAddress* get_EthSrc() {return src;};
	// a c�mzett ethernet c�me (ethernet headerbol)
	__property EthernetAddress* get_EthDst() {return dst;};
	
	virtual String *ToString();
	// a csomag kereszt�lfuttat�sa a megadott ellenorzon
	virtual CheckResult* accept(Checker* checker, CheckResult* in);

protected:
	// Ha nem virtual, akkor mindig az os-osztalybelit hivna meg a createPacket();
	virtual Packet* createInstance(PacketInfo *in) {return new EthernetPacket(in);};

	EthernetAddress *src, *dst;
	u_short type;
};

// **********************************************************************************
// Az ARP csomagot implemental� csomag oszt�ly
public __gc class ARPPacket : public EthernetPacket {
public:
	ARPPacket() : EthernetPacket() {};
	ARPPacket(PacketInfo *in);

	// hardware c�m t�pusa
	__property u_short get_HType() {return htype;};
	// protokoll c�m t�pusa
	__property u_short get_PType() {return ptype;};
	// hardware c�m hossza
	__property u_char get_HLen() {return hlen;};
	// protokoll c�m hossza
	__property u_char get_PLen() {return plen;};
	// muvelet tipusa
	__property u_short get_Operation() {return operation;};

	// forras hardware cim
	__property EthernetAddress* get_ARPSrcHAddr() {return src_eth;};
	// forras protokoll cim
	__property IPv4Address* get_ARPSrcPAddr() {return src_ip;};
	// cel hardware cim
	__property EthernetAddress* get_ARPDstHAddr() {return dest_eth;};
	// cel protokoll cim
	__property IPv4Address* get_ARPDstPAddr() {return dest_ip;};

	// Megpr�b�lja feldolgozni a csomagot. Visszat�r�si �rt�ke NULL, ha ez sikertelen
	virtual Packet* createPacket(PacketInfo* in);

	virtual String *ToString();
	// a csomag kereszt�lfuttat�sa a megadott ellenorzon
	virtual CheckResult* accept(Checker* checker, CheckResult* in);

	// az ARP k�r�s k�dja
	const static u_short OP_REQUEST = 1;
	// az ARP v�lasz k�dja
	const static u_short OP_REPLY = 2;
	// a RARP k�r�s k�dja
	const static u_short OP_RREQUEST = 3;
	// a RARP v�lasz k�dja
	const static u_short OP_RREPLY = 4;

protected:
	// Ha nem virtual, akkor mindig az os-osztalybelit hivna meg a createPacket();
	virtual Packet* createInstance(PacketInfo *in) {return new ARPPacket(in);};

	// hardware c�m t�pusa
	u_short htype;
	// protokoll c�m t�pusa
	u_short ptype;
	// hardware c�m m�rete
	u_char hlen;
	// protokoll c�m m�rete
	u_char plen;
	// muvelet t�pusa
	u_short operation;
	EthernetAddress *src_eth;
	IPv4Address *src_ip;
	EthernetAddress *dest_eth;
	IPv4Address *dest_ip;

	EthernetAddress *src, *dst;
	u_short type;
};

// **********************************************************************************
// Az IPv4 csomagot megval�s�t� oszt�ly
public __gc class IPv4Packet : public EthernetPacket {
public:
	IPv4Packet() : EthernetPacket() {};
	IPv4Packet(PacketInfo *in);

	// IP verzi� (fixen 4)
	__property u_char get_Version() {return version;};
	// az IP fejl�c hossza
	__property u_char get_HeaderLength() {return hlen;};
	// az IP csomagba z�rt protokoll
	__property u_char get_Protocol() {return pid;};
	// az IP csomag forr�s c�me
	__property IPv4Address* get_IPv4SrcAddr() {return src_ip;};
	// az IP csomag c�l c�me
	__property IPv4Address* get_IPv4DstAddr() {return dst_ip;};

	// Megpr�b�lja feldolgozni a csomagot. Visszat�r�si �rt�ke NULL, ha ez sikertelen
	virtual Packet* createPacket(PacketInfo* in);

	virtual String *ToString();
	// a csomag kereszt�lfuttat�sa a megadott ellenorzon
	virtual CheckResult* accept(Checker* checker, CheckResult* in);

protected:
	// Ha nem virtual, akkor mindig az os-osztalybelit hivna meg a createPacket();
	virtual Packet* createInstance(PacketInfo *in) {return new IPv4Packet(in);};

	u_char version;
	u_char hlen;
	u_char pid;
	
	IPv4Address* src_ip;
	IPv4Address* dst_ip;
};

// **********************************************************************************
// az UDP csomag megval�s�t�sa
public __gc class UDPPacket : public IPv4Packet {
public:
	UDPPacket() : IPv4Packet() {};
	UDPPacket(PacketInfo *in);

	// az UDP forr�s portja
	__property u_short get_UDPSrcPort() {return src_port;};
	// az UDP c�l portja
	__property u_short get_UDPDstPort() {return dst_port;};

	// Megpr�b�lja feldolgozni a csomagot. Visszat�r�si �rt�ke NULL, ha ez sikertelen
	virtual Packet* createPacket(PacketInfo* in);

	virtual String *ToString();
	// a csomag kereszt�lfuttat�sa a megadott ellenorzon
	virtual CheckResult* accept(Checker* checker, CheckResult* in);

protected:
	// Ha nem virtual, akkor mindig az os-osztalybelit hivna meg a createPacket();
	virtual Packet* createInstance(PacketInfo *in) {return new UDPPacket(in);};

	u_short src_port;
	u_short dst_port;
};

// **********************************************************************************
// A DHCP/BOOTP csomag megval�s�t�sa
public __gc class DHCPPacket : public UDPPacket {
public:
	DHCPPacket() : UDPPacket() {};
	DHCPPacket(PacketInfo *in);

	// hardver cim tipusa
	__property u_char get_HType() {return htype;};
	// hardver cim hossza (byte-ban)
	__property u_char get_HLen() {return hlen;};
	// DHCP csomag tipusa
	__property u_char get_Type() {return type;};
	// kliens hardver cime
	__property EthernetAddress* get_DHCPClientHAddr() {return client_eth;};
	// kliens protokoll cime
	__property IPv4Address* get_DHCPClientPAddr() {return client_ip;};

	// Megpr�b�lja feldolgozni a csomagot. Visszat�r�si �rt�ke NULL, ha ez sikertelen
	virtual Packet* createPacket(PacketInfo* in);

	virtual String *ToString();
	// a csomag kereszt�lfuttat�sa a megadott ellenorzon
	virtual CheckResult* accept(Checker* checker, CheckResult* in);

	// a DHCP k�r�s k�dja
	const static u_char DHCP_REQUEST = 1;
	// a DHCP v�lasz k�dja
	const static u_char DHCP_REPLY = 2; 

protected:
	// Ha nem virtual, akkor mindig az os-osztalybelit hivna meg a createPacket();
	virtual Packet* createInstance(PacketInfo *in) {return new DHCPPacket(in);};

	u_char type;
	u_char htype;
	u_char hlen;
	
	EthernetAddress* client_eth;
	IPv4Address* client_ip;
};

// **********************************************************************************
// A winpcap �ltal visszaadott adaptert foglalja mag�ba */
public __gc class Adapter {
public:
	Adapter(pcap_if *_adapter);

	// TRUE, ha loopback adapter */
	bool isLoopback();
	// visszaadja az adapter IP-cimet (ha van)
	IPv4Address* getIPv4Address() {return ipaddr;};
	// visszaadja az adapter nev�t
	String* getID() {return new String(adapter->name);};

	// megnyitja az adaptert a csomagok elfog�s�hoz. A caplen jelzi, hogy
	// mekkora a maxim�lis csomagm�ret.Az enn�l nagyobb csomagokat 
	// csonk�tva fogja el, vagyis a caplen feletti r�szt lev�gja
	void open(int caplen);
	// lez�rja az adaptert
	void close();
	// szuro felt�tel megad�sa az adapternek. A libpcap �ltal ismert
	// felt�teles kifejez�sek adhat�ak meg
	void setFilter(char* filter);
	
	// csomag elfog�sa. Blokkolja a h�v� sz�lat, am�g nem siker�l elfogni
	// egy csomagot. Ez a winpcap hib�ja, egy�bk�nt egy 100ms -os timeout-
	// tal t�rt�nik a h�v�s
	Packet* read();

	// Az adapter neve
	String* ToString();

protected:
	pcap_if* adapter;
	pcap_t* adhandle;
	IPv4Address* ipaddr;
};

// **********************************************************************************
// Az adaptereket �sszefog� oszt�ly
public __gc class AdapterManager {
public:
	AdapterManager();
	~AdapterManager();

	// az adapterek sz�m�nak lek�rdez�se
	int adapterNum() {return adapter->Count;};
	// a k�rt indexu adapter elk�r�se
	Adapter* getAdapter(int which);

protected:
	ArrayList *adapter;
};

// **********************************************************************************
// a csomag objektumot l�trehoz� statikus met�dust tartalmazza
public __gc class PacketFactory {
public:
	static PacketFactory() {
		p = new Packet();
		EthernetPacket* ep = new EthernetPacket();
		p->addChild(ep);
		ARPPacket* ap = new ARPPacket();
		ep->addChild(ap);
		IPv4Packet* ipv4 = new IPv4Packet();
		ep->addChild(ipv4);
		UDPPacket* udp = new UDPPacket();
		ipv4->addChild(udp);
		DHCPPacket* dhcp = new DHCPPacket();
		udp->addChild(dhcp);
	}

	// l�trehozza a csomag objektumot a PacketInfo* -b�l
	static Packet* createPacket(PacketInfo* pi) {
		return p->createPacket(pi);
	}

private:
	static Packet *p;
};
}