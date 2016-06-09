
#define NTDDI_VERSION NTDDI_WINBLUE

#include <winsock2.h>
#include <ws2tcpip.h>

#include <windows.h>
#include <fwpmu.h>

#include <stdio.h>

int main(int argc, const char** argv) {

	DWORD status;

	if (argc!=2) {
		printf("This program requires one argument, the name of the host to block.");
		return 0;
	}

	printf("Atttempting to block access to %s\n", argv[1]);

	WORD wVersionRequested;
	WSADATA wsaData;
	int err;

	wVersionRequested = MAKEWORD(2, 2);

	status = WSAStartup(wVersionRequested, &wsaData);
	printf("WSAStartup result %x\n", (unsigned)status);
	if (status != ERROR_SUCCESS) {                       
		printf("WSAStartup failed\n");
		return status;
	}

	ADDRINFOA hints;
	RtlZeroMemory(&hints, sizeof(ADDRINFOA));
	hints.ai_flags = AI_V4MAPPED;

	PADDRINFOA AddressInfo;
	status = getaddrinfo(argv[1], "http", &hints, &AddressInfo);
	printf("getaddrinfo result %x\n", (unsigned)status);
	WSACleanup();
	if (status != ERROR_SUCCESS) {
		printf("failed to resolve %s\n", argv[1]);
		return status;
	}
	
	UCHAR* addressData = AddressInfo->ai_addr->sa_data + 2;
	UINT32 ipAddress = (addressData[0]<<24)| (addressData[1] << 16) | (addressData[2] << 8) | (addressData[3] << 0);
	printf("%s resolved to %d.%d.%d.%d (0x%x)\n", argv[1], addressData[0], addressData[1], addressData[2], addressData[3], ipAddress);

	HANDLE FwpmHandle;

	status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &FwpmHandle);
	
	FWPM_FILTER0 filter;

	printf("FwpmEngineOpen0 result code %x\n", status);
	if (status != ERROR_SUCCESS) {
		return status;
	}

	printf("FwpmEngine started %x\n", (unsigned)FwpmHandle);

	RtlZeroMemory(&filter, sizeof(FWPM_FILTER0));

	filter.displayData.name = L"Filtering test.";
	filter.flags = FWPM_FILTER_FLAG_NONE;
	filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
	filter.action.type = FWP_ACTION_BLOCK;
	filter.weight.type = FWP_EMPTY; // auto-weight.

	filter.numFilterConditions = 1;

	FWP_V4_ADDR_AND_MASK addr_and_mask;
	RtlZeroMemory(&addr_and_mask, sizeof(addr_and_mask));
	addr_and_mask.addr = ipAddress; //0x2EE42F73
	addr_and_mask.mask = 0xFFFFFFFF;

	FWPM_FILTER_CONDITION0 filterCondition;
	RtlZeroMemory(&filterCondition, sizeof(filterCondition));
	
	filter.filterCondition = &filterCondition;
	filterCondition.matchType = FWP_MATCH_EQUAL;
	filterCondition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
	filterCondition.conditionValue.type = FWP_V4_ADDR_MASK;
	filterCondition.conditionValue.v4AddrMask = &addr_and_mask;
	
	UINT64 filterId;
	status = FwpmFilterAdd0(FwpmHandle, &filter, NULL, &filterId);

	printf("FwpmFilterAdd0 result code %x\n", status);
	if (status != ERROR_SUCCESS) {
		return status;
	}

	printf("Blocking %s\nPress any key to stop\n", argv[1]);
	char readChar;
	scanf_s("%c",&readChar);

	status = FwpmFilterDeleteById0(FwpmHandle, filterId);

	printf("FwpmFilterDeleteById0 result code %x\n", status);
	if (status != ERROR_SUCCESS) {
		printf("Failed to remove filter!!!!\n");
		return status;
	} else {
		printf("Filtering stopped.\n");
	}
	
	return 0;
}