#pragma once
#include "AdapterTab.h"
#include "PacketCaptureThread.h"

using namespace System;
using namespace System::ComponentModel;
using namespace System::Collections;
using namespace System::Windows::Forms;
using namespace System::Data;
using namespace System::Drawing;

namespace ARPWatch {
// a fo urlapot megjeleníto osztály
public __gc class MainForm : public System::Windows::Forms::Form {

private:
	// az al-urlapokat tárolja
	ArrayList *tabs;
	// a régi ablakméret, átméretezéshez
	System::Drawing::Size oldSize;

public: 
	MainForm() {
		InitializeComponent();
			
		tabs = new ArrayList();
		oldSize = InterfaceTabControl->Size;
	}

	// új fül létrehozása - példányosít egy új AdapterTab objektumot
	AdapterTab *addAdapter(PacketCaptureThread* pct) {
		AdapterTab *newAdapterTab = new AdapterTab(pct);
		InterfaceTabControl->SuspendLayout();
		InterfaceTabControl->Controls->Add(newAdapterTab->getAdapterTab());
		InterfaceTabControl->ResumeLayout();
		tabs->Add(newAdapterTab);
		return newAdapterTab;
	}
        
protected: 
	void Dispose(Boolean disposing) {
		if (disposing && components) {
			components->Dispose();
		}
		__super::Dispose(disposing);
	}

private: System::Windows::Forms::TabControl *  InterfaceTabControl;

private:
		System::ComponentModel::Container* components;

		void InitializeComponent(void)
		{
			this->InterfaceTabControl = new System::Windows::Forms::TabControl();
			this->SuspendLayout();
			// 
			// InterfaceTabControl
			// 
			this->InterfaceTabControl->Anchor = (System::Windows::Forms::AnchorStyles)(((System::Windows::Forms::AnchorStyles::Top | System::Windows::Forms::AnchorStyles::Bottom) 
				| System::Windows::Forms::AnchorStyles::Left) 
				| System::Windows::Forms::AnchorStyles::Right);
			this->InterfaceTabControl->Location = System::Drawing::Point(0, 0);
			this->InterfaceTabControl->Name = S"InterfaceTabControl";
			this->InterfaceTabControl->SelectedIndex = 0;
			this->InterfaceTabControl->Size = System::Drawing::Size(792, 472);
			this->InterfaceTabControl->TabIndex = 0;
			this->InterfaceTabControl->Resize += new System::EventHandler(this, InterfaceTabControl_Resize);
			// 
			// MainForm
			// 
			this->AutoScaleBaseSize = System::Drawing::Size(5, 13);
			this->ClientSize = System::Drawing::Size(792, 472);
			this->Controls->Add(this->InterfaceTabControl);
			this->MinimumSize = System::Drawing::Size(200, 300);
			this->Name = S"MainForm";
			this->Text = S"NetWatch";
			this->ResumeLayout(false);

		}		



private:


	/** Ez azert kell, mert az anchor valami miatt nem mukodott, igy inkabb en implementaltam */
	System::Void InterfaceTabControl_Resize(System::Object *  sender, System::EventArgs *  e) {
		Control* control = dynamic_cast<Control*>(sender);

		System::Drawing::Size diff = control->Size - oldSize;
		for (int i = 0; i < tabs->Count; i++) {
			AdapterTab* actTab = dynamic_cast<AdapterTab*>(tabs->Item[i]);
			actTab->resize(diff);
		}
		oldSize = control->Size;
	}
};
}