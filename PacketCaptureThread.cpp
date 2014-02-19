#include "PacketCaptureThread.h"
#include "AdapterTab.h"

using namespace ARPWatch;
using namespace System::Globalization;

// **********************************************************************************
PacketCaptureThread::PacketCaptureThread(Adapter* _adapter, Checker* _checker) : adapter(_adapter), checker(_checker), state(STATE_INIT) {
	thread = new Thread(new ThreadStart(this, &PacketCaptureThread::threadProc));
	adapterName = adapter->ToString();
	adapterID = adapter->getID();
	adapterIP = adapter->getIPv4Address();
	if (!EventLog::SourceExists(eventLogSource))
		EventLog::CreateEventSource(eventLogSource, eventLogLog);
	fileLogMonitor = new Object();
}

// **********************************************************************************
void PacketCaptureThread::Start() {
	if (state == STATE_INIT_SUSPENDED) {
		thread->Start();
		thread->Suspend();
		state = STATE_SUSPENDED;
	} else if (state == STATE_INIT) {
		StartCapture();
		thread->Start();
		state = STATE_RUNNING;
	}
}

void PacketCaptureThread::Abort() {
	if (state == STATE_SUSPENDED) {
		state = STATE_ABORTING;
		thread->Resume();
		thread->Abort();
	} else if (state == STATE_RUNNING || state == STATE_BACK_FROM_SUSPEND) {
		state = STATE_ABORTING;
		thread->Abort();
		StopCapture();
	} /*else {
		Windows::Forms::MessageBox::Show((new Int32(state))->ToString());
	}*/
	adapterTab->saveConfig();
	if (fileLog) fileLog->Close();
}

void PacketCaptureThread::Suspend() {
	if (state == STATE_INIT) {
		state = STATE_INIT_SUSPENDED;
		return;
	}
	if (state != STATE_RUNNING && state != STATE_BACK_FROM_SUSPEND) return;
	thread->Suspend();
	StopCapture();
	state = STATE_SUSPENDED;
}

void PacketCaptureThread::Resume() {
	if (state == STATE_INIT_SUSPENDED) {
		state = STATE_INIT;
		return;
	}

	if (state != STATE_SUSPENDED) return;
	StartCapture();
	state = STATE_BACK_FROM_SUSPEND;
	thread->Resume();
}

// **********************************************************************************
void PacketCaptureThread::StartCapture() {
	adapter->open(512);	// ennyi boven elég, hiszen mi csak a fejléceket vizsgáljuk, nem érdekel az adat
	adapter->setFilter("udp or arp or rarp");
}

void PacketCaptureThread::StopCapture() {
	adapter->close();
}

// **********************************************************************************
void PacketCaptureThread::set_FileLogName(String* in) {
	Monitor::Enter(fileLogMonitor);
	if (in) {
		fileLog = new StreamWriter(in, true, System::Text::Encoding::ASCII);
	} else {
		if (fileLog) fileLog->Close();
	}
	fileLogName = in;
	Monitor::Exit(fileLogMonitor);
}

// **********************************************************************************
void PacketCaptureThread::threadProc() {
	for (int VCDOTNETBUG = 0; ; VCDOTNETBUG++) {
		try {
			VCDOTNETBUG--;
			// status beallitas - ha nem történt exception
			if (state == STATE_BACK_FROM_SUSPEND)
				state = STATE_RUNNING;
			
			// csomag elfogás - addig várakoztatja a szálat, amíg csomag nem jött
			Packet* p = adapter->read();
			CheckResult* cr = p->accept(checker, NULL);
			String* message = p->ToString();
			DateTime capTS = p->TimeStamp;
			String* captureTime = (new StringBuilder(capTS.ToString(S"yy-MM-dd", DateTimeFormatInfo::InvariantInfo)))->Append(" ")->Append(capTS.ToString(S"T", DateTimeFormatInfo::InvariantInfo))->ToString();

			// display
			for (int i = 0; i < cr->Count; i++)
				adapterTab->addItem(cr->Warning[i]);
			if (!displayWarningsOnly) adapterTab->addItem(p->ToString());

			// filelog
			Monitor::Enter(fileLogMonitor);
			if (fileLogName) {
				for (int i = 0; i < cr->Count; i++) {
					StringBuilder* sb = new StringBuilder(captureTime);
					sb->Append(S"\t")->Append(cr->Warning[i]);
					fileLog->WriteLine(sb->ToString());
				}
				if (!fileLogWarningsOnly) {
					StringBuilder* sb = new StringBuilder(captureTime);
					sb->Append(S"\t")->Append(message);
					fileLog->WriteLine(sb->ToString());
				}
			}
			Monitor::Exit(fileLogMonitor);
	
			// event log
			if (eventLogEnabled) {
				for (int i = 0; i < cr->Count; i++) {
					StringBuilder* sb = new StringBuilder(captureTime);
					sb->Append(S"\t")->Append(cr->Warning[i]);
					EventLog::WriteEntry(eventLogSource, sb->ToString());
				}
				if (!eventLogWarningsOnly) {
					StringBuilder* sb = new StringBuilder(captureTime);
					sb->Append(S"\t")->Append(message);
					EventLog::WriteEntry(eventLogSource, sb->ToString(), EventLogEntryType::Warning);
				}
			}

		} catch (ThreadAbortException*) {
			// ez normalis
		} catch (Exception* e) {
			switch(state) {
				case STATE_BACK_FROM_SUSPEND: state = STATE_RUNNING; break;
				case STATE_ABORTING: Thread::Sleep(100); break;
				default: System::Windows::Forms::MessageBox::Show(e->ToString());
			}
		}
	}
}
