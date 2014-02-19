#include "stdafx.h"
#include "AdapterTab.h"

using namespace Microsoft::Win32;

namespace ARPWatch {

AdapterTab::AdapterTab(PacketCaptureThread* pct) {
	InitializeComponent();
	fileLogName = S"";
	displayLines = 100;

	pct->setAdapterTab(this);
	packetCaptureThread = pct;
	loadConfig();

	adapterTab = new TabPage();

	String* adapterIP = pct->getAdapterIP()->ToString();
	String* adapterName = pct->getAdapterName();

	IPAddressL->Text = adapterIP;

	StringBuilder* sb = new StringBuilder();
	if (adapterName->Length < 20) sb->Append(adapterName);
	else sb->Append(adapterName->Substring(0,20))->Append(S"...");
		
	sb->Append(S" (")->Append(adapterIP)->Append(S")");

	String* tabLabel = sb->ToString();
	adapterTab->Text = tabLabel;
			
	adapterTab->SuspendLayout();
	adapterTab->Controls->Add(this->groupBox3);
	adapterTab->Controls->Add(this->groupBox2);
	adapterTab->Controls->Add(this->groupBox1);
	adapterTab->Controls->Add(this->label1);
	adapterTab->Controls->Add(this->LogGB);
	adapterTab->Controls->Add(this->PacketLB);
	adapterTab->ResumeLayout();
	PacketLBSize = PacketLB->Size;
}

void AdapterTab::addItem(String *item) {
	PacketLB->BeginUpdate();
	int i = displayLines;
	if (i > 0) {
		while (PacketLB->Items->Count > i) {
			PacketLB->Items->RemoveAt(0);
		}
	}
	PacketLB->Items->Add(item);
	PacketLB->EndUpdate();
}

void AdapterTab::resize(System::Drawing::Size diff) {
	PacketLBSize = PacketLBSize + diff;
	PacketLB->Size = PacketLBSize;
}

void AdapterTab::loadConfig() {
	String* adapterID = packetCaptureThread->getAdapterID();
	RegistryKey *rk = Registry::CurrentUser;
	rk = rk ->OpenSubKey((new StringBuilder(S"Software\\NetWatch\\"))->Append(adapterID)->ToString());
	if (!rk) return;	// nem letezik
	
	CaptureEnabledCB->Checked = Convert::ToBoolean(rk->GetValue(S"CaptureEnabled")->ToString());

	fileLogName = Convert::ToString(rk->GetValue(S"FileLogName"));
	FileLogNameTB->Text = Convert::ToString(rk->GetValue(S"FileLogName"));
	FileLogEnabledCB->Checked = Convert::ToBoolean(rk->GetValue(S"FileLogEnabled")->ToString());
	FileLogWarningsOnlyCB->Checked = Convert::ToBoolean(rk->GetValue(S"FileLogWarningsOnly")->ToString());

	DisplayWarningsOnlyCB->Checked = Convert::ToBoolean(rk->GetValue(S"DisplayWarningsOnly")->ToString());
	displayLines = Convert::ToInt32(rk->GetValue(S"DisplayLines"));
	if (displayLines > 0) {
		DisplayLinesTB->Text = Convert::ToString(displayLines);
	} else {
		DisplayLinesTB->Text = S"";
	}
	
	EventLogEnabledCB->Checked = Convert::ToBoolean(rk->GetValue(S"EventLogEnabled")->ToString());
	EventLogWarningsOnlyCB->Checked = Convert::ToBoolean(rk->GetValue(S"EventLogWarningsOnly")->ToString());
}

void AdapterTab::saveConfig() {
	String* adapterID = packetCaptureThread->getAdapterID();
	String* regKey = (new StringBuilder(S"Software\\NetWatch\\"))->Append(adapterID)->ToString();
	RegistryKey *rk = Registry::CurrentUser;
	try {
		rk->DeleteSubKeyTree(regKey);
	} catch (System::ArgumentException*) {}
	rk->CreateSubKey(regKey);
	rk = rk ->OpenSubKey(regKey, true);

	rk->SetValue(S"CaptureEnabled", (CaptureEnabledCB->Checked?S"True":"False"));

	rk->SetValue(S"FileLogEnabled", (FileLogEnabledCB->Checked?S"True":"False"));
	rk->SetValue(S"FileLogWarningsOnly", (FileLogWarningsOnlyCB->Checked?S"True":"False"));
	rk->SetValue(S"FileLogName", fileLogName);

	rk->SetValue(S"DisplayWarningsOnly", (DisplayWarningsOnlyCB->Checked?S"True":"False"));
	rk->SetValue(S"DisplayLines", Convert::ToString(displayLines));

	rk->SetValue(S"EventLogEnabled", (EventLogEnabledCB->Checked?S"True":"False"));
	rk->SetValue(S"EventLogWarningsOnly", (EventLogWarningsOnlyCB->Checked?S"True":"False"));
}

}