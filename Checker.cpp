#include "Checker.h"

using namespace System::Text;
using namespace System::IO;
using namespace ARPWatch;

String* KnowledgeBaseItem::SerializeText() {
	StringBuilder* sb = new StringBuilder(50);
	sb->Append(captureTime.ToString(S"yy-MM-dd T"))->Append(S"\t");
	sb->Append(captureAdapter->SerializeText());	// ide nem kell szeparator, mert ez lesz a sor vege
	return sb->ToString();
}

Object* KnowledgeBaseItem::DeSerializeText(String* in) {
	String* split[] = in->Split(DELIMITER_TAB);
	if (split->Count != 2) throw new ApplicationException((new StringBuilder(S"Split count != 2 in: "))->Append(in)->ToString());
	
	KnowledgeBaseItem* kbi = new KnowledgeBaseItem();
	
	// DateTime deserialization
	String* dts[] = split[0]->Split(DELIMITER_DATETIME);
	if (dts->Count != 6) throw new ApplicationException((new StringBuilder(S"DateTime split count != 6 in: "))->Append(split[0])->ToString());
	
	captureTime = DateTime(Int32::Parse(dts[0]), Int32::Parse(dts[1]), Int32::Parse(dts[2]), Int32::Parse(dts[3]), Int32::Parse(dts[4]), Int32::Parse(dts[5]));

	// captureAdapter serialization
	kbi->captureAdapter = new IPv4Address(split[1]);

	return kbi;
}

String* IPv4AddressInfo::SerializeText() {
	StringBuilder* sb = new StringBuilder(50);
	sb->Append(addr->SerializeText())->Append(S"\t");
	sb->Append(KnowledgeBaseItem::SerializeText());
	return sb->ToString();
}

Object* IPv4AddressInfo::DeSerializeText(String* in) {
	String* split[] = in->Split(DELIMITER_TAB, 2);
	if (split->Count != 2) throw new ApplicationException((new StringBuilder(S"Split count != 2 in: "))->Append(in)->ToString());
	
	IPv4AddressInfo* ipai = new IPv4AddressInfo();
	ipai->addr = new IPv4Address(split[0]);
	KnowledgeBaseItem::DeSerializeText(split[1]);
	return ipai;
}

String* EthernetAddressInfo::SerializeText() {
	StringBuilder* sb = new StringBuilder(50);
	sb->Append(addr->SerializeText())->Append(S"\t");
	sb->Append(KnowledgeBaseItem::SerializeText());
	return sb->ToString();
}

Object* EthernetAddressInfo::DeSerializeText(String* in) {
	String* split[] = in->Split(DELIMITER_TAB, 2);
	if (split->Count != 2) throw new ApplicationException((new StringBuilder(S"Split count != 2 in: "))->Append(in)->ToString());
	
	EthernetAddressInfo* eai = new EthernetAddressInfo();
	eai->addr = new EthernetAddress(split[0]);
	KnowledgeBaseItem::DeSerializeText(split[1]);
	return eai;
}

void KnowledgeBase::save() {
	StreamWriter* sw = new StreamWriter(name, false, System::Text::Encoding::ASCII);
	IDictionaryEnumerator __gc *en = KB->GetEnumerator();
	while (en->MoveNext()) {
		KnowledgeBaseItemSerializer* key = __try_cast<KnowledgeBaseItemSerializer*>(en->Key);
		KnowledgeBaseItemSerializer* value = __try_cast<KnowledgeBaseItemSerializer*>(en->Value);

		sw->Write(key->SerializeText());
		sw->Write(S"\t");
		sw->WriteLine(value->SerializeText());
	}
	sw->Close();
}

void KnowledgeBase::load() {
	try {
		StreamReader* sr = new StreamReader(name, System::Text::Encoding::ASCII);
	
		while (String* line = sr->ReadLine()) {
			if (line->Length < 1) continue;	// üres sorok kiszurése

			String* split[] = line->Split(KnowledgeBaseItem::DELIMITER_TAB, 2);
			Object* key = keySkel->DeSerializeText(split[0]);
			Object* val = valSkel->DeSerializeText(split[1]);
		
			KB->Item[key] = val;
		}
	} catch (IOException*) {
		// nem letezik vagy hibas az adatfile - kilepeskor ujrairjuk, itt nincs mit tenni
	}
}

void Checker::saveKB() {
	for (int i = 0; i < KB->Count; i++)
		KB[i]->save();
}

void Checker::loadKB() {
	for (int i = 0; i < KB->Count; i++)
		KB[i]->load();
}

// Üres; csak a keretrendszer egysegessege miatt letezik
CheckResult* Checker::visitPacket(Packet* in, CheckResult *cr) {
	if (cr) return cr;
	return new CheckResult();
}

// **********************************************************************************
CheckResult* Checker::visitEthernetPacket(EthernetPacket* in, CheckResult* cr) {
	CheckResult* ret = cr?cr:new CheckResult();
	// specialis forras ethernet csomagokkal nem foglalkozunk
	if (in->EthSrc->isSpecial()) return ret;

	IPv4Address* actval = static_cast<IPv4Address*>(KBEthAdapter->Item[in->EthSrc]);
	IPv4Address* gotval = in->CaptureAdapter->getIPv4Address();

	if (!actval) {
		KBEthAdapter->Item[in->EthSrc] = gotval;
		ret->addWarning((new StringBuilder(S"New ethernet address "))->Append(in->EthSrc->ToString())->Append(S" found on interface ")->Append(gotval->ToString())->ToString());
	} else {
		if (!actval->Equals(gotval)) {
			KBEthAdapter->Item[in->EthSrc] = gotval;	// felülírjuk a meglevo értéket, hogy csak egy warningot dobjon
			ret->addWarning((new StringBuilder(S"Ethernet address "))->Append(in->EthSrc->ToString())
				->Append(S" previously found on interface ")->Append(actval->ToString())->Append(S" found on interface ")->Append(gotval->ToString())->ToString());
		}
	}
	return ret;
}

// **********************************************************************************
String* Checker::checkIPEthAddress(IPv4Address* ip, EthernetAddress* eth) {
	EthernetAddress* actval = static_cast<EthernetAddress*>(KBIPEth->Item[ip]);
	
	if (!actval) {
		KBIPEth->Item[ip] = eth;
		return (new StringBuilder(S"New Ethernet address "))->Append(eth->ToString())->Append(S" found for IP address ")->Append(ip->ToString())->ToString();
	} else {
		if (!actval->Equals(eth)) {
			KBIPEth->Item[ip] = eth;
			return (new StringBuilder(S"New ethernet address "))->Append(eth->ToString())->Append(S" found for IP address ")->Append(ip->ToString())->Append(" (old ethernet address is ")->Append(actval->ToString())->Append(S")")->ToString();
		} else {
			return NULL;
		}
	}
}

// **********************************************************************************
String* Checker::checkEthIPAddress(EthernetAddress* eth, IPv4Address* ip) {
	IPv4Address* actval = static_cast<IPv4Address*>(KBEthIP->Item[eth]);
	
	if (!actval) {
		KBEthIP->Item[eth] = ip;
		return (new StringBuilder(S"New IP address "))->Append(ip->ToString())->Append(S" found for Ethernet address ")->Append(eth->ToString())->ToString();
	} else {
		if (!actval->Equals(ip)) {
			KBEthIP->Item[eth] = ip;
			return (new StringBuilder(S"New IP address "))->Append(ip->ToString())->Append(S" found for Ethernet address ")->Append(eth->ToString())->Append(" (old IP address is ")->Append(actval->ToString())->Append(S")")->ToString();
		} else {
			return NULL;
		}
	}
}

// **********************************************************************************
CheckResult* Checker::visitARPPacket(ARPPacket* in, CheckResult *cr) {
	CheckResult* ret = cr?cr:new CheckResult();
	
	// forrás címek ellenorzése
	if (!in->ARPSrcHAddr->isSpecial() && !in->ARPSrcPAddr->isSpecial()) {
		String* s = checkEthIPAddress(in->ARPSrcHAddr, in->ARPSrcPAddr);
		if (s) ret->addWarning((new StringBuilder(s))->Append(S" in an ARP packet's source fields sent from ")->Append(in->EthSrc->ToString())->ToString());

		s = checkIPEthAddress(in->ARPSrcPAddr, in->ARPSrcHAddr);
		if (s) ret->addWarning((new StringBuilder(s))->Append(S" in an ARP packet's source fields sent from ")->Append(in->EthSrc->ToString())->ToString());
	}

	// cél címek ellenorzése
	if (!in->ARPDstHAddr->isSpecial() && !in->ARPDstPAddr->isSpecial()) {
		String* s = checkEthIPAddress(in->ARPDstHAddr, in->ARPDstPAddr);
		if (s) ret->addWarning((new StringBuilder(s))->Append(S" in an ARP packet's destionation fields sent from ")->Append(in->EthSrc->ToString())->ToString());

		s = checkIPEthAddress(in->ARPDstPAddr, in->ARPDstHAddr);
		if (s) ret->addWarning((new StringBuilder(s))->Append(S" in an ARP packet's destination fields sent from ")->Append(in->EthSrc->ToString())->ToString());
	}

	return ret;
}

// **********************************************************************************
CheckResult* Checker::visitIPv4Packet(IPv4Packet* in, CheckResult *cr) {
	CheckResult* ret = cr?cr:new CheckResult();

	// forrás címek ellenorzése
	if (!in->EthSrc->isSpecial() && !in->IPv4SrcAddr->isSpecial()) {
		String* s = checkEthIPAddress(in->EthSrc, in->IPv4SrcAddr);
		if (s) ret->addWarning((new StringBuilder(s))->Append(S" in an IP packet's source fields sent from ")->Append(in->EthSrc->ToString())->ToString());

		s = checkIPEthAddress(in->IPv4SrcAddr, in->EthSrc);
		if (s) ret->addWarning((new StringBuilder(s))->Append(S" in an IP packet's source fields sent from ")->Append(in->EthSrc->ToString())->ToString());
	}

	// cél címek ellenorzése
	if (!in->EthDst->isSpecial() && !in->IPv4DstAddr->isSpecial()) {
		String* s = checkEthIPAddress(in->EthDst, in->IPv4DstAddr);
		if (s) ret->addWarning((new StringBuilder(s))->Append(S" in an IP packet's destination fields sent from ")->Append(in->EthSrc->ToString())->ToString());

		s = checkIPEthAddress(in->IPv4DstAddr, in->EthDst);
		if (s) ret->addWarning((new StringBuilder(s))->Append(S" in an IP packet's destination fields sent from ")->Append(in->EthSrc->ToString())->ToString());
	}

	return ret;
}

// **********************************************************************************
CheckResult* Checker::visitUDPPacket(UDPPacket* in, CheckResult *cr) {
	CheckResult* ret = cr?cr:new CheckResult();
	return ret;
}

// **********************************************************************************
CheckResult* Checker::visitDHCPPacket(DHCPPacket* in, CheckResult *cr) {
	CheckResult* ret = cr?cr:new CheckResult();

	// címek ellenorzése
	if (!in->DHCPClientHAddr->isSpecial() && !in->DHCPClientPAddr->isSpecial()) {
		String* s = checkEthIPAddress(in->DHCPClientHAddr, in->DHCPClientPAddr);
		if (s) ret->addWarning((new StringBuilder(s))->Append(S" in a DHCP packet's source fields sent from ")->Append(in->EthSrc->ToString())->Append(S", ")->Append(in->IPv4SrcAddr->ToString())->ToString());

		s = checkIPEthAddress(in->DHCPClientPAddr, in->DHCPClientHAddr);
		if (s) ret->addWarning((new StringBuilder(s))->Append(S" in a DHCP packet's source fields sent from ")->Append(in->EthSrc->ToString())->Append(S", ")->Append(in->IPv4SrcAddr->ToString())->ToString());
	}

	return ret;
}