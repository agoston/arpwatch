#pragma once
#include "pcap_classes.h"

using namespace System::Threading;
using namespace System::IO;
using namespace System::Diagnostics;

namespace ARPWatch {
// Predefiníció az adapterTab -hoz
public __gc class AdapterTab;

// az elfogó szál
__sealed public __gc class PacketCaptureThread {
private:
	AdapterTab* adapterTab;
	Adapter* adapter;
	Thread* thread;
	Checker* checker;

	String* adapterName;
	String* adapterID;
	IPv4Address* adapterIP;

	String* fileLogName;
	bool fileLogWarningsOnly;
	bool displayWarningsOnly;
	bool eventLogWarningsOnly;
	bool eventLogEnabled;

	// a napló file hozzáférés-szabályozását végzo monitor
	Object* fileLogMonitor;
	StreamWriter* fileLog;
	static String* eventLogSource = S"NetWatch";
	static String* eventLogLog = S"Application";

	int state;
	static const STATE_RUNNING = 0;
	static const STATE_SUSPENDED = 1;
	static const STATE_ABORTING = 2;
	static const STATE_INIT = 3;
	static const STATE_INIT_SUSPENDED = 4;
	static const STATE_BACK_FROM_SUSPEND = 5;

public:
	PacketCaptureThread(Adapter* _adapter, Checker* _checker);

	// a szál által futtatott metódus
	void threadProc();

	// a csatoló neve
	String* getAdapterName() {return adapterName;};
	// a csatoló azonosítója
	String* getAdapterID() {return adapterID;};
	// a csatoló IP-címe
	IPv4Address* getAdapterIP() {return adapterIP;};
	void setAdapterTab(AdapterTab* at) {adapterTab = at;};

	void Start();
	void Abort();
	void Suspend();
	void Resume();

	__property void set_FileLogName(String* in);
	__property void set_FileLogWarningsOnly(bool in) {fileLogWarningsOnly = in;};
	__property void set_DisplayWarningsOnly(bool in) {displayWarningsOnly = in;};
	__property void set_EventLogWarningsOnly(bool in) {eventLogWarningsOnly = in;};
	__property void set_EventLogEnabled(bool in) {eventLogEnabled = in;};

private:
	// a WinPcap csomag-elfogásának indítása
	void StartCapture();
	// a WinPcap csomag-elfogásának leállítása
	void StopCapture();
};
}