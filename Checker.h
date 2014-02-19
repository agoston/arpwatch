#pragma once
#include "pcap_classes.h"

namespace ARPWatch {

// **********************************************************************************
// alap osztály a tudásbázisok értékeinek egyszeru bovítéséhez
// nyilvántartja az elfogás idejét és az azt végzo csatolót is
public __gc class KnowledgeBaseItem : public KnowledgeBaseItemSerializer {
private:
	DateTime captureTime;
	IPv4Address* captureAdapter;

public:
	__property DateTime get_CaptureTime() {return captureTime;};
	__property IPv4Address* get_CaptureAdapter() {return captureAdapter;};

	virtual String* SerializeText();
	virtual Object* DeSerializeText(String* in);

	static const __wchar_t DELIMITER_TAB __gc[] = S"\t"->ToCharArray();
	static const __wchar_t DELIMITER_DATETIME __gc[] = S"- :"->ToCharArray();
};

// **********************************************************************************
// az IPv4 címen kívül nyilvántartja az elfogás idejét és az elfogást végzo csatolót is
public __gc class IPv4AddressInfo : public KnowledgeBaseItem {
private:
	IPv4Address* addr;

public:
	__property IPv4Address* get_Address() {return addr;};

	virtual String* SerializeText();
	virtual Object* DeSerializeText(String* in);

};

// **********************************************************************************
// az ethernet címen kívül nyilvántartja az elfogás idejét és az elfogást végzo csatolót is
public __gc class EthernetAddressInfo : public KnowledgeBaseItem {
private:
	EthernetAddress* addr;

public:
	__property EthernetAddress* get_Address() {return addr;};

	virtual String* SerializeText();
	virtual Object* DeSerializeText(String* in);
};

// **********************************************************************************
// a tudásbázisokat és a hozzájuk kapcsolódo adatokat és muveleteket tartalmazó objektum
public __gc class KnowledgeBase {
private:
	// a tudásbázist tartalmazó Hashtable objektum
	Hashtable* KB;
	// a tudásbázis neve
	String* name;
	// a tudásbázis kulcsaként használt objektumból egy példány
	KnowledgeBaseItemSerializer* keySkel;
	// a tudásbázis értékeként használt objektumból egy példány
	KnowledgeBaseItemSerializer* valSkel;

public:
	KnowledgeBase(String* _name, Hashtable* _KB, KnowledgeBaseItemSerializer* _key, KnowledgeBaseItemSerializer* _val) : 
	  KB(_KB), name(_name), keySkel(_key), valSkel(_val) {};

	// a tudásbázis elmentése
	void save();
	// a tudásbázis betöltése
	void load();
};

// **********************************************************************************
public __gc class Checker {
public:
	CheckResult* visitPacket(Packet* in, CheckResult* cr);
	CheckResult* visitEthernetPacket(EthernetPacket* in, CheckResult *cr);
	CheckResult* visitARPPacket(ARPPacket* in, CheckResult *cr);
	CheckResult* visitIPv4Packet(IPv4Packet* in, CheckResult *cr);
	CheckResult* visitUDPPacket(UDPPacket* in, CheckResult *cr);
	CheckResult* visitDHCPPacket(DHCPPacket* in, CheckResult *cr);

	// tudásbázisok kimentése
	static void saveKB();
	// tudásbázisok betöltése
	static void loadKB();

protected:

	// segédfüggvény az IP-Ethernet címpárok teszteléséhez
	String* checkIPEthAddress(IPv4Address* ip, EthernetAddress* eth);
	// segédfüggvény az Ethernet-IP címpárok teszteléséhez
	String* checkEthIPAddress(EthernetAddress* eth, IPv4Address* ip);

	// A hashtable elméletileg lehetové teszi ugyan, hogy eltéro típusú kulcsokat használjunk,
	// gyakorlatban azonban inkább nehézségeket jelent, mint valódi elonyt
	static Hashtable* KBEthAdapter = Hashtable::Synchronized(new Hashtable());
	static Hashtable* KBIPEth = Hashtable::Synchronized(new Hashtable());
	static Hashtable* KBEthIP = Hashtable::Synchronized(new Hashtable());

	// a tudásbázisokat tartalmazó tömb
	static KnowledgeBase* KB __gc[] = {
		new KnowledgeBase(S"EthAdapter.tab", KBEthAdapter, new EthernetAddress(-1), new IPv4Address(-1)),
		new KnowledgeBase(S"IPEth.tab", KBIPEth, new IPv4Address(-1), new EthernetAddress(-1)),
		new KnowledgeBase(S"EthIP.tab", KBEthIP, new EthernetAddress(-1), new IPv4Address(-1))
	};
};

}