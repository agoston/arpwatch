#pragma once

#include "pcap.h"
//#include "Checker.h"
// VC.NET BUG workaround: a windows.h -ban definialt makro .net framework alatt csak zavaro
#undef MessageBox

using namespace System;
using namespace System::Collections;

namespace ARPWatch {

// predefinició a Checker-hez
public __gc class Checker;

// a szérializációhoz használt interfész
public __gc __interface KnowledgeBaseItemSerializer {
	String* SerializeText();
	Object* DeSerializeText(String* in);
};

// **********************************************************************************
// Kihasználjuk, hogy az IPv4 cím belefér az unsigned long -ba, ami jóval hatékonyabb egy __gc[] -nél
public __gc class IPv4Address : public KnowledgeBaseItemSerializer {
public:
	IPv4Address(u_long _address) {address = _address;};
	IPv4Address(String* in);
	IPv4Address(u_char* _address);

	String *ToString();
	// hash-ként az ip címet adja vissza, mert pont jó
	int GetHashCode() {return address;};
	bool Equals(Object* in);
	// igaz, ha null- vagy broadcast cím
	bool isSpecial() {return address==0 || address==0xffffffff;};

	String* SerializeText();
	Object* DeSerializeText(String* in);

protected:
	u_long address;
};

// **********************************************************************************
// Kihasználjuk, hogy az ethernet cím belefér az __int64 -be, ami jóval hatékonyabb egy __gc[] -nél
public __gc class EthernetAddress : public KnowledgeBaseItemSerializer {
public:
	EthernetAddress(u_char* _address);
	EthernetAddress(__int64 _address) {address = _address;};
	EthernetAddress(String* in);
	
	String *ToString();
	int GetHashCode() {return (int)((address&0xffffff) ^ (address>>24));};
	bool Equals(Object* in);
	// igaz, ha null- vagy broadcast cím
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

	// A csomag elejébol és végébol nyes le
	void crop(int header, int footer);
	// visszaállítja az eredeti, nyesetlen állapotot
	void reset() {retLen = len; retData = data;};

	// a csomag valódi hossza
	__property int get_RealLength() {return len;};
	// a csomag valódi tartalma
	__property u_char *get_RealData() {return data;};
	// a csomag nyesett hossza
	__property int get_Length() {return retLen;};
	// a csomag nyesett tartalma
	__property u_char *get_Data() {return retData;};
	// az elfogás idobélyege
	__property DateTime get_TimeStamp() {return timeStamp;};
	// az elfogást végzo adapter
	__property Adapter* get_CaptureAdapter() {return captureAdapter;};

	String *ToString();

protected:
	u_char *data, *retData;
	int len, retLen;
	DateTime timeStamp;
	Adapter* captureAdapter;
};

// **********************************************************************************
// az ellenorzés eredményeit tároló osztály
public __gc class CheckResult {
private:
	ArrayList* warnings;

public:
	CheckResult() {warnings = new ArrayList();};

	// új figyelmeztetés megadása
	void addWarning(String* warn) {warnings->Add(warn);};

	// figyelmeztetések számának lekérdezése
	__property int get_Count() {return warnings->Count;};
	// a megadott sorszámú figyelmeztetés lekérdezése
	__property String* get_Warning(int i) {return static_cast<String*>(warnings->Item[i]);};
};

// **********************************************************************************
// Minden Packet osztály ose
public __gc class Packet {
public:
	Packet() {child = new Packet* [0];};
	Packet(PacketInfo *in) : pi(in) {pi->reset();};

	// az elfogás ideje
	__property DateTime get_TimeStamp() {return pi->TimeStamp;};
	// az elfogó adapter
	__property Adapter* get_CaptureAdapter() {return pi->CaptureAdapter;};

	// Megpróbálja feldolgozni a csomagot. Visszatérési értéke NULL, ha ez sikertelen
	virtual Packet* createPacket(PacketInfo* in);
	// új gyerek megadása a csomag-fában
	void addChild(Packet* p);

	virtual String* ToString();
	// a csomag keresztülfuttatása a megadott ellenorzon
	virtual CheckResult* accept(Checker* checker, CheckResult* in);

protected:
	// Ha nem virtual, akkor mindig az os-osztalybelit hivna meg a createPacket();
	virtual Packet* createInstance(PacketInfo *in) {return new Packet(in);};
	// A hierarchia felépítésére szolgál
	Packet* child __gc[];

	PacketInfo *pi;
};

// **********************************************************************************
// Az ethernetcsomag osztály. Annyival több a nyers csomagnál, hogy értelmezi az ethernet csomag
// fejlécét, benne a küldo és a címzett ethernet címével
public __gc class EthernetPacket : public Packet {
public:
	EthernetPacket() : Packet() {};
	EthernetPacket(PacketInfo *in);

	// a forrás ethernet címe (ethernet headerbol)
	__property EthernetAddress* get_EthSrc() {return src;};
	// a címzett ethernet címe (ethernet headerbol)
	__property EthernetAddress* get_EthDst() {return dst;};
	
	virtual String *ToString();
	// a csomag keresztülfuttatása a megadott ellenorzon
	virtual CheckResult* accept(Checker* checker, CheckResult* in);

protected:
	// Ha nem virtual, akkor mindig az os-osztalybelit hivna meg a createPacket();
	virtual Packet* createInstance(PacketInfo *in) {return new EthernetPacket(in);};

	EthernetAddress *src, *dst;
	u_short type;
};

// **********************************************************************************
// Az ARP csomagot implementaló csomag osztály
public __gc class ARPPacket : public EthernetPacket {
public:
	ARPPacket() : EthernetPacket() {};
	ARPPacket(PacketInfo *in);

	// hardware cím típusa
	__property u_short get_HType() {return htype;};
	// protokoll cím típusa
	__property u_short get_PType() {return ptype;};
	// hardware cím hossza
	__property u_char get_HLen() {return hlen;};
	// protokoll cím hossza
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

	// Megpróbálja feldolgozni a csomagot. Visszatérési értéke NULL, ha ez sikertelen
	virtual Packet* createPacket(PacketInfo* in);

	virtual String *ToString();
	// a csomag keresztülfuttatása a megadott ellenorzon
	virtual CheckResult* accept(Checker* checker, CheckResult* in);

	// az ARP kérés kódja
	const static u_short OP_REQUEST = 1;
	// az ARP válasz kódja
	const static u_short OP_REPLY = 2;
	// a RARP kérés kódja
	const static u_short OP_RREQUEST = 3;
	// a RARP válasz kódja
	const static u_short OP_RREPLY = 4;

protected:
	// Ha nem virtual, akkor mindig az os-osztalybelit hivna meg a createPacket();
	virtual Packet* createInstance(PacketInfo *in) {return new ARPPacket(in);};

	// hardware cím típusa
	u_short htype;
	// protokoll cím típusa
	u_short ptype;
	// hardware cím mérete
	u_char hlen;
	// protokoll cím mérete
	u_char plen;
	// muvelet típusa
	u_short operation;
	EthernetAddress *src_eth;
	IPv4Address *src_ip;
	EthernetAddress *dest_eth;
	IPv4Address *dest_ip;

	EthernetAddress *src, *dst;
	u_short type;
};

// **********************************************************************************
// Az IPv4 csomagot megvalósító osztály
public __gc class IPv4Packet : public EthernetPacket {
public:
	IPv4Packet() : EthernetPacket() {};
	IPv4Packet(PacketInfo *in);

	// IP verzió (fixen 4)
	__property u_char get_Version() {return version;};
	// az IP fejléc hossza
	__property u_char get_HeaderLength() {return hlen;};
	// az IP csomagba zárt protokoll
	__property u_char get_Protocol() {return pid;};
	// az IP csomag forrás címe
	__property IPv4Address* get_IPv4SrcAddr() {return src_ip;};
	// az IP csomag cél címe
	__property IPv4Address* get_IPv4DstAddr() {return dst_ip;};

	// Megpróbálja feldolgozni a csomagot. Visszatérési értéke NULL, ha ez sikertelen
	virtual Packet* createPacket(PacketInfo* in);

	virtual String *ToString();
	// a csomag keresztülfuttatása a megadott ellenorzon
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
// az UDP csomag megvalósítása
public __gc class UDPPacket : public IPv4Packet {
public:
	UDPPacket() : IPv4Packet() {};
	UDPPacket(PacketInfo *in);

	// az UDP forrás portja
	__property u_short get_UDPSrcPort() {return src_port;};
	// az UDP cél portja
	__property u_short get_UDPDstPort() {return dst_port;};

	// Megpróbálja feldolgozni a csomagot. Visszatérési értéke NULL, ha ez sikertelen
	virtual Packet* createPacket(PacketInfo* in);

	virtual String *ToString();
	// a csomag keresztülfuttatása a megadott ellenorzon
	virtual CheckResult* accept(Checker* checker, CheckResult* in);

protected:
	// Ha nem virtual, akkor mindig az os-osztalybelit hivna meg a createPacket();
	virtual Packet* createInstance(PacketInfo *in) {return new UDPPacket(in);};

	u_short src_port;
	u_short dst_port;
};

// **********************************************************************************
// A DHCP/BOOTP csomag megvalósítása
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

	// Megpróbálja feldolgozni a csomagot. Visszatérési értéke NULL, ha ez sikertelen
	virtual Packet* createPacket(PacketInfo* in);

	virtual String *ToString();
	// a csomag keresztülfuttatása a megadott ellenorzon
	virtual CheckResult* accept(Checker* checker, CheckResult* in);

	// a DHCP kérés kódja
	const static u_char DHCP_REQUEST = 1;
	// a DHCP válasz kódja
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
// A winpcap által visszaadott adaptert foglalja magába */
public __gc class Adapter {
public:
	Adapter(pcap_if *_adapter);

	// TRUE, ha loopback adapter */
	bool isLoopback();
	// visszaadja az adapter IP-cimet (ha van)
	IPv4Address* getIPv4Address() {return ipaddr;};
	// visszaadja az adapter nevét
	String* getID() {return new String(adapter->name);};

	// megnyitja az adaptert a csomagok elfogásához. A caplen jelzi, hogy
	// mekkora a maximális csomagméret.Az ennél nagyobb csomagokat 
	// csonkítva fogja el, vagyis a caplen feletti részt levágja
	void open(int caplen);
	// lezárja az adaptert
	void close();
	// szuro feltétel megadása az adapternek. A libpcap által ismert
	// feltételes kifejezések adhatóak meg
	void setFilter(char* filter);
	
	// csomag elfogása. Blokkolja a hívó szálat, amíg nem sikerül elfogni
	// egy csomagot. Ez a winpcap hibája, egyébként egy 100ms -os timeout-
	// tal történik a hívás
	Packet* read();

	// Az adapter neve
	String* ToString();

protected:
	pcap_if* adapter;
	pcap_t* adhandle;
	IPv4Address* ipaddr;
};

// **********************************************************************************
// Az adaptereket összefogó osztály
public __gc class AdapterManager {
public:
	AdapterManager();
	~AdapterManager();

	// az adapterek számának lekérdezése
	int adapterNum() {return adapter->Count;};
	// a kért indexu adapter elkérése
	Adapter* getAdapter(int which);

protected:
	ArrayList *adapter;
};

// **********************************************************************************
// a csomag objektumot létrehozó statikus metódust tartalmazza
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

	// létrehozza a csomag objektumot a PacketInfo* -ból
	static Packet* createPacket(PacketInfo* pi) {
		return p->createPacket(pi);
	}

private:
	static Packet *p;
};
}