#include "stdafx.h"
#include "MainForm.h"
#include "PacketCaptureThread.h"
#include "Checker.h"

using namespace System;
using namespace System::Threading;
using namespace ARPWatch;

int APIENTRY _tWinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPTSTR    lpCmdLine,
                     int       nCmdShow)
{
try {

	System::Threading::Thread::CurrentThread->ApartmentState = System::Threading::ApartmentState::STA;

	// inicializaljuk a tudasbazist
	Checker* checker = new Checker();
	checker->loadKB();

	// letrehozzuk a fuleket
	MainForm *app = new MainForm();
	AdapterManager *am = new AdapterManager;
	PacketCaptureThread *thread[] = new PacketCaptureThread* __gc[am->adapterNum()];

	for (int i = 0; i < thread->Count; i++) {
		Adapter* actad = am->getAdapter(i);
		IPv4Address* ipa = actad->getIPv4Address();
		if (!ipa) continue;	// ha nincs IPv4 cime, nem jelenitjuk meg

		PacketCaptureThread *newpct = new PacketCaptureThread(actad, checker);
		AdapterTab* newat = app->addAdapter(newpct);

		thread[i] = newpct;
	}

	// es végül thread indítás következik
	for (int i = 0; i < thread->Count; i++) {
		if (thread[i]) thread[i]->Start();
	}

	// GUI indul
	Application::Run(app);

	// thread-ek leallitasa
	for (int i = 0; i < thread->Count; i++) {
		if (thread[i]) thread[i]->Abort();
	}
	
	// mivel a thread-ek mar halottak, nincs gond a KB kiirasaval, nem fog valtozni
	checker->saveKB();

	return 0;
} catch (Exception *e) {
	// ha biba történt, arról mindig dobjunk üzenetet
	MessageBox::Show(e->ToString(), S"NetWatch error");
}

}