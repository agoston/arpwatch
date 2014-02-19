#pragma once
#include "pcap_classes.h"
#include "PacketCaptureThread.h"

using namespace System;
using namespace System::ComponentModel;
using namespace System::Collections;
using namespace System::Windows::Forms;
using namespace System::Data;
using namespace System::Drawing;
using namespace System::Text;

namespace ARPWatch {
// az egy csatolóhoz tartozó fület megvalósító osztály
public __gc class AdapterTab : public System::Windows::Forms::Form {
private:
	// a fület kirajzoló objektum
	TabPage* adapterTab;

	// az átméretezéshez szükséges méretet tárolja
	System::Drawing::Size PacketLBSize;
	// referencia a csatolóhoz tartozó szálra
	PacketCaptureThread* packetCaptureThread;
	// log file neve
	String* fileLogName;
	// megjelenített sorok száma
	int displayLines;

public:
	TabPage *getAdapterTab() {return adapterTab;};
	AdapterTab(PacketCaptureThread* pct);

	// uj információ megjelenítése a listában
	void addItem(String *item);
	// a fül átméretezését végzi
	void resize(System::Drawing::Size diff);

	// a konfiguráció betöltése a registry-bol
	void loadConfig();
	// a konfiguráció kimentése a registry-be
	void saveConfig();

protected: 
	void Dispose(Boolean disposing) {
		if (disposing && components) {
			components->Dispose();
		}
		__super::Dispose(disposing);
	}


private: System::Windows::Forms::CheckBox *  FileLogWarningsOnlyCB;
private: System::Windows::Forms::CheckBox *  CaptureEnabledCB;
private: System::Windows::Forms::CheckBox *  FileLogEnabledCB;
private: System::Windows::Forms::TextBox *  FileLogNameTB;
private: System::Windows::Forms::CheckBox *  EventLogWarningsOnlyCB;
private: System::Windows::Forms::CheckBox *  EventLogEnabledCB;

	private: System::Windows::Forms::GroupBox *  LogGB;
	private: System::Windows::Forms::Label *  label1;
	private: System::Windows::Forms::GroupBox *  groupBox1;

	private: System::Windows::Forms::GroupBox *  groupBox2;
	private: System::Windows::Forms::CheckBox *  DisplayWarningsOnlyCB;

	private: System::Windows::Forms::GroupBox *  groupBox3;

	private: System::Windows::Forms::TextBox *  DisplayLinesTB;
	private: System::Windows::Forms::Label *  label2;
	private: System::Windows::Forms::Label *  label3;
	private: System::Windows::Forms::Label *  IPAddressL;
	private: System::Windows::Forms::ListBox *  PacketLB;

private:
	System::ComponentModel::Container* components;

		void InitializeComponent(void)
		{
			this->FileLogEnabledCB = new System::Windows::Forms::CheckBox();
			this->PacketLB = new System::Windows::Forms::ListBox();
			this->FileLogNameTB = new System::Windows::Forms::TextBox();
			this->LogGB = new System::Windows::Forms::GroupBox();
			this->FileLogWarningsOnlyCB = new System::Windows::Forms::CheckBox();
			this->label1 = new System::Windows::Forms::Label();
			this->groupBox1 = new System::Windows::Forms::GroupBox();
			this->IPAddressL = new System::Windows::Forms::Label();
			this->label3 = new System::Windows::Forms::Label();
			this->CaptureEnabledCB = new System::Windows::Forms::CheckBox();
			this->groupBox2 = new System::Windows::Forms::GroupBox();
			this->label2 = new System::Windows::Forms::Label();
			this->DisplayLinesTB = new System::Windows::Forms::TextBox();
			this->DisplayWarningsOnlyCB = new System::Windows::Forms::CheckBox();
			this->groupBox3 = new System::Windows::Forms::GroupBox();
			this->EventLogWarningsOnlyCB = new System::Windows::Forms::CheckBox();
			this->EventLogEnabledCB = new System::Windows::Forms::CheckBox();
			this->LogGB->SuspendLayout();
			this->groupBox1->SuspendLayout();
			this->groupBox2->SuspendLayout();
			this->groupBox3->SuspendLayout();
			this->SuspendLayout();
			// 
			// FileLogEnabledCB
			// 
			this->FileLogEnabledCB->Location = System::Drawing::Point(16, 48);
			this->FileLogEnabledCB->Name = S"FileLogEnabledCB";
			this->FileLogEnabledCB->TabIndex = 1;
			this->FileLogEnabledCB->Text = S"Log to file:";
			this->FileLogEnabledCB->CheckedChanged += new System::EventHandler(this, FileLogEnabledCB_CheckedChanged);
			// 
			// PacketLB
			// 
			this->PacketLB->Location = System::Drawing::Point(8, 160);
			this->PacketLB->Name = S"PacketLB";
			this->PacketLB->Size = System::Drawing::Size(768, 277);
			this->PacketLB->TabIndex = 2;
			// 
			// FileLogNameTB
			// 
			this->FileLogNameTB->Location = System::Drawing::Point(16, 72);
			this->FileLogNameTB->Name = S"FileLogNameTB";
			this->FileLogNameTB->Size = System::Drawing::Size(136, 20);
			this->FileLogNameTB->TabIndex = 3;
			this->FileLogNameTB->Text = S"";
			this->FileLogNameTB->TextChanged += new System::EventHandler(this, FileLogNameTB_TextChanged);
			// 
			// LogGB
			// 
			this->LogGB->Controls->Add(this->FileLogWarningsOnlyCB);
			this->LogGB->Controls->Add(this->FileLogEnabledCB);
			this->LogGB->Controls->Add(this->FileLogNameTB);
			this->LogGB->ForeColor = System::Drawing::SystemColors::ControlText;
			this->LogGB->Location = System::Drawing::Point(192, 16);
			this->LogGB->Name = S"LogGB";
			this->LogGB->Size = System::Drawing::Size(168, 104);
			this->LogGB->TabIndex = 4;
			this->LogGB->TabStop = false;
			this->LogGB->Text = S"File log";
			// 
			// FileLogWarningsOnlyCB
			// 
			this->FileLogWarningsOnlyCB->Checked = true;
			this->FileLogWarningsOnlyCB->CheckState = System::Windows::Forms::CheckState::Checked;
			this->FileLogWarningsOnlyCB->Location = System::Drawing::Point(16, 16);
			this->FileLogWarningsOnlyCB->Name = S"FileLogWarningsOnlyCB";
			this->FileLogWarningsOnlyCB->TabIndex = 4;
			this->FileLogWarningsOnlyCB->Text = S"Warnings only";
			this->FileLogWarningsOnlyCB->CheckedChanged += new System::EventHandler(this, FileLogWarningsOnlyCB_CheckedChanged);
			// 
			// label1
			// 
			this->label1->Location = System::Drawing::Point(8, 136);
			this->label1->Name = S"label1";
			this->label1->Size = System::Drawing::Size(100, 16);
			this->label1->TabIndex = 5;
			this->label1->Text = S"Capture results:";
			// 
			// groupBox1
			// 
			this->groupBox1->Controls->Add(this->IPAddressL);
			this->groupBox1->Controls->Add(this->label3);
			this->groupBox1->Controls->Add(this->CaptureEnabledCB);
			this->groupBox1->Location = System::Drawing::Point(16, 16);
			this->groupBox1->Name = S"groupBox1";
			this->groupBox1->Size = System::Drawing::Size(168, 104);
			this->groupBox1->TabIndex = 6;
			this->groupBox1->TabStop = false;
			this->groupBox1->Text = S"Adapter";
			// 
			// IPAddressL
			// 
			this->IPAddressL->Location = System::Drawing::Point(16, 72);
			this->IPAddressL->Name = S"IPAddressL";
			this->IPAddressL->Size = System::Drawing::Size(144, 16);
			this->IPAddressL->TabIndex = 10;
			this->IPAddressL->Text = S"Unknown";
			// 
			// label3
			// 
			this->label3->Location = System::Drawing::Point(16, 56);
			this->label3->Name = S"label3";
			this->label3->Size = System::Drawing::Size(64, 16);
			this->label3->TabIndex = 9;
			this->label3->Text = S"IP Address:";
			// 
			// CaptureEnabledCB
			// 
			this->CaptureEnabledCB->Checked = true;
			this->CaptureEnabledCB->CheckState = System::Windows::Forms::CheckState::Checked;
			this->CaptureEnabledCB->Location = System::Drawing::Point(16, 16);
			this->CaptureEnabledCB->Name = S"CaptureEnabledCB";
			this->CaptureEnabledCB->TabIndex = 8;
			this->CaptureEnabledCB->Text = S"Capture";
			this->CaptureEnabledCB->CheckedChanged += new System::EventHandler(this, CaptureCB_CheckedChanged);
			// 
			// groupBox2
			// 
			this->groupBox2->Controls->Add(this->label2);
			this->groupBox2->Controls->Add(this->DisplayLinesTB);
			this->groupBox2->Controls->Add(this->DisplayWarningsOnlyCB);
			this->groupBox2->Location = System::Drawing::Point(368, 16);
			this->groupBox2->Name = S"groupBox2";
			this->groupBox2->Size = System::Drawing::Size(120, 104);
			this->groupBox2->TabIndex = 7;
			this->groupBox2->TabStop = false;
			this->groupBox2->Text = S"Display";
			// 
			// label2
			// 
			this->label2->Location = System::Drawing::Point(16, 56);
			this->label2->Name = S"label2";
			this->label2->Size = System::Drawing::Size(48, 16);
			this->label2->TabIndex = 6;
			this->label2->Text = S"Rows:";
			// 
			// DisplayLinesTB
			// 
			this->DisplayLinesTB->Location = System::Drawing::Point(16, 72);
			this->DisplayLinesTB->Name = S"DisplayLinesTB";
			this->DisplayLinesTB->Size = System::Drawing::Size(56, 20);
			this->DisplayLinesTB->TabIndex = 5;
			this->DisplayLinesTB->Text = S"100";
			this->DisplayLinesTB->TextChanged += new System::EventHandler(this, DisplayLinesTB_TextChanged);
			// 
			// DisplayWarningsOnlyCB
			// 
			this->DisplayWarningsOnlyCB->Checked = true;
			this->DisplayWarningsOnlyCB->CheckState = System::Windows::Forms::CheckState::Checked;
			this->DisplayWarningsOnlyCB->Location = System::Drawing::Point(16, 16);
			this->DisplayWarningsOnlyCB->Name = S"DisplayWarningsOnlyCB";
			this->DisplayWarningsOnlyCB->Size = System::Drawing::Size(96, 24);
			this->DisplayWarningsOnlyCB->TabIndex = 4;
			this->DisplayWarningsOnlyCB->Text = S"Warnings only";
			this->DisplayWarningsOnlyCB->CheckedChanged += new System::EventHandler(this, DisplayWarningsOnlyCB_CheckedChanged);
			// 
			// groupBox3
			// 
			this->groupBox3->Controls->Add(this->EventLogWarningsOnlyCB);
			this->groupBox3->Controls->Add(this->EventLogEnabledCB);
			this->groupBox3->Location = System::Drawing::Point(496, 16);
			this->groupBox3->Name = S"groupBox3";
			this->groupBox3->Size = System::Drawing::Size(168, 72);
			this->groupBox3->TabIndex = 8;
			this->groupBox3->TabStop = false;
			this->groupBox3->Text = S"Event log";
			// 
			// EventLogWarningsOnlyCB
			// 
			this->EventLogWarningsOnlyCB->Checked = true;
			this->EventLogWarningsOnlyCB->CheckState = System::Windows::Forms::CheckState::Checked;
			this->EventLogWarningsOnlyCB->Location = System::Drawing::Point(16, 40);
			this->EventLogWarningsOnlyCB->Name = S"EventLogWarningsOnlyCB";
			this->EventLogWarningsOnlyCB->TabIndex = 5;
			this->EventLogWarningsOnlyCB->Text = S"Warnings only";
			this->EventLogWarningsOnlyCB->CheckedChanged += new System::EventHandler(this, EventLogWarningsOnlyCB_CheckedChanged);
			// 
			// EventLogEnabledCB
			// 
			this->EventLogEnabledCB->Location = System::Drawing::Point(16, 16);
			this->EventLogEnabledCB->Name = S"EventLogEnabledCB";
			this->EventLogEnabledCB->TabIndex = 4;
			this->EventLogEnabledCB->Text = S"Log to event log";
			this->EventLogEnabledCB->CheckedChanged += new System::EventHandler(this, EventLogEnabledCB_CheckedChanged);
			// 
			// AdapterTab
			// 
			this->AutoScaleBaseSize = System::Drawing::Size(5, 13);
			this->ClientSize = System::Drawing::Size(784, 444);
			this->Controls->Add(this->groupBox3);
			this->Controls->Add(this->groupBox2);
			this->Controls->Add(this->groupBox1);
			this->Controls->Add(this->label1);
			this->Controls->Add(this->LogGB);
			this->Controls->Add(this->PacketLB);
			this->Name = S"AdapterTab";
			this->Text = S"DeleteMe";
			this->LogGB->ResumeLayout(false);
			this->groupBox1->ResumeLayout(false);
			this->groupBox2->ResumeLayout(false);
			this->groupBox3->ResumeLayout(false);
			this->ResumeLayout(false);

		}		
private: 
	System::Void CaptureCB_CheckedChanged(System::Object *  sender, System::EventArgs *  e) {
		if (CaptureEnabledCB->Checked) packetCaptureThread->Resume();
		else packetCaptureThread->Suspend();
	}

private: System::Void FileLogEnabledCB_CheckedChanged(System::Object *  sender, System::EventArgs *  e)
		 {
			 if (FileLogEnabledCB->Checked) {
				 if (FileLogNameTB->Text->Length <= 0) {
					 Windows::Forms::MessageBox::Show(S"Enter the log file name before enabling logging to file");
					 FileLogEnabledCB->Checked = false;
					 return;
				 }
                 FileLogNameTB->Enabled = false;
				 packetCaptureThread->FileLogName = FileLogNameTB->Text;
			 } else {
				 FileLogNameTB->Enabled = true;
				 packetCaptureThread->FileLogName = NULL;
			 }
			 fileLogName = FileLogNameTB->Text;
		 }

private: System::Void DisplayLinesTB_TextChanged(System::Object *  sender, System::EventArgs *  e)
		 {
			 if (DisplayLinesTB->TextLength > 0) {
				 try {
					 displayLines = Convert::ToInt32(DisplayLinesTB->Text);
				 } catch (Exception*) {
					 Windows::Forms::MessageBox::Show(S"Enter a numeric value");
					 DisplayLinesTB->Text = Convert::ToString(displayLines);
				 }
			 } else {
				 displayLines = -1;
			 }
		 }
private: System::Void DisplayWarningsOnlyCB_CheckedChanged(System::Object *  sender, System::EventArgs *  e)
		 {
			 packetCaptureThread->DisplayWarningsOnly = DisplayWarningsOnlyCB->Checked;
		 }

private: System::Void FileLogWarningsOnlyCB_CheckedChanged(System::Object *  sender, System::EventArgs *  e)
		 {
			 packetCaptureThread->FileLogWarningsOnly = FileLogWarningsOnlyCB->Checked;
		 }

private: System::Void EventLogEnabledCB_CheckedChanged(System::Object *  sender, System::EventArgs *  e)
		 {
			 packetCaptureThread->EventLogEnabled = EventLogEnabledCB->Checked;
		 }

private: System::Void EventLogWarningsOnlyCB_CheckedChanged(System::Object *  sender, System::EventArgs *  e)
		 {
			 packetCaptureThread->EventLogWarningsOnly = EventLogWarningsOnlyCB->Checked;
		 }

private: System::Void FileLogNameTB_TextChanged(System::Object *  sender, System::EventArgs *  e)
		 {
			 fileLogName = FileLogNameTB->Text;
		 }

};
}