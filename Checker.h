#pragma once
#include "pcap_classes.h"

namespace ARPWatch {

// **********************************************************************************
// alap oszt�ly a tud�sb�zisok �rt�keinek egyszeru bov�t�s�hez
// nyilv�ntartja az elfog�s idej�t �s az azt v�gzo csatol�t is
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
// az IPv4 c�men k�v�l nyilv�ntartja az elfog�s idej�t �s az elfog�st v�gzo csatol�t is
public __gc class IPv4AddressInfo : public KnowledgeBaseItem {
private:
	IPv4Address* addr;

public:
	__property IPv4Address* get_Address() {return addr;};

	virtual String* SerializeText();
	virtual Object* DeSerializeText(String* in);

};

// **********************************************************************************
// az ethernet c�men k�v�l nyilv�ntartja az elfog�s idej�t �s az elfog�st v�gzo csatol�t is
public __gc class EthernetAddressInfo : public KnowledgeBaseItem {
private:
	EthernetAddress* addr;

public:
	__property EthernetAddress* get_Address() {return addr;};

	virtual String* SerializeText();
	virtual Object* DeSerializeText(String* in);
};

// **********************************************************************************
// a tud�sb�zisokat �s a hozz�juk kapcsol�do adatokat �s muveleteket tartalmaz� objektum
public __gc class KnowledgeBase {
private:
	// a tud�sb�zist tartalmaz� Hashtable objektum
	Hashtable* KB;
	// a tud�sb�zis neve
	String* name;
	// a tud�sb�zis kulcsak�nt haszn�lt objektumb�l egy p�ld�ny
	KnowledgeBaseItemSerializer* keySkel;
	// a tud�sb�zis �rt�kek�nt haszn�lt objektumb�l egy p�ld�ny
	KnowledgeBaseItemSerializer* valSkel;

public:
	KnowledgeBase(String* _name, Hashtable* _KB, KnowledgeBaseItemSerializer* _key, KnowledgeBaseItemSerializer* _val) : 
	  KB(_KB), name(_name), keySkel(_key), valSkel(_val) {};

	// a tud�sb�zis elment�se
	void save();
	// a tud�sb�zis bet�lt�se
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

	// tud�sb�zisok kiment�se
	static void saveKB();
	// tud�sb�zisok bet�lt�se
	static void loadKB();

protected:

	// seg�df�ggv�ny az IP-Ethernet c�mp�rok tesztel�s�hez
	String* checkIPEthAddress(IPv4Address* ip, EthernetAddress* eth);
	// seg�df�ggv�ny az Ethernet-IP c�mp�rok tesztel�s�hez
	String* checkEthIPAddress(EthernetAddress* eth, IPv4Address* ip);

	// A hashtable elm�letileg lehetov� teszi ugyan, hogy elt�ro t�pus� kulcsokat haszn�ljunk,
	// gyakorlatban azonban ink�bb neh�zs�geket jelent, mint val�di elonyt
	static Hashtable* KBEthAdapter = Hashtable::Synchronized(new Hashtable());
	static Hashtable* KBIPEth = Hashtable::Synchronized(new Hashtable());
	static Hashtable* KBEthIP = Hashtable::Synchronized(new Hashtable());

	// a tud�sb�zisokat tartalmaz� t�mb
	static KnowledgeBase* KB __gc[] = {
		new KnowledgeBase(S"EthAdapter.tab", KBEthAdapter, new EthernetAddress(-1), new IPv4Address(-1)),
		new KnowledgeBase(S"IPEth.tab", KBIPEth, new IPv4Address(-1), new EthernetAddress(-1)),
		new KnowledgeBase(S"EthIP.tab", KBEthIP, new EthernetAddress(-1), new IPv4Address(-1))
	};
};

}