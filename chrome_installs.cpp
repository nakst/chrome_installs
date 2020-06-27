#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <windows.h>
#include <commctrl.h> 
#include <shellscalingapi.h>

#pragma comment(linker,"\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#define STB_DS_IMPLEMENTATION
#include "stb_ds.h"

HWND root, label1, label2, progress;
intptr_t countResult;

#pragma pack(push,1)
struct BootSector {
	uint8_t	 jump[3]; 
	char	 name[8];
	uint16_t bytesPerSector;
	uint8_t	 sectorsPerCluster;
	uint16_t reservedSectors;
	uint8_t	 unused0[3];
	uint16_t unused1;
	uint8_t	 media;
	uint16_t unused2;
	uint16_t sectorsPerTrack;
	uint16_t headsPerCylinder;
	uint32_t hiddenSectors;
	uint32_t unused3;
	uint32_t unused4;
	uint64_t totalSectors;
	uint64_t mftStart;
	uint64_t mftMirrorStart;
	uint32_t clustersPerFileRecord;
	uint32_t clustersPerIndexBlock;
	uint64_t serialNumber;
	uint32_t checksum;
	uint8_t	 bootloader[426];
	uint16_t bootSignature;
};

struct FileRecordHeader {
	uint32_t magic;
	uint16_t updateSequenceOffset;
	uint16_t updateSequenceSize;
	uint64_t logSequence;
	uint16_t sequenceNumber;
	uint16_t hardLinkCount;
	uint16_t firstAttributeOffset;
	uint16_t inUse : 1;
	uint16_t isDirectory : 1;
	uint32_t usedSize;
	uint32_t allocatedSize;
	uint64_t fileReference;
	uint16_t nextAttributeID;
	uint16_t unused;
	uint32_t recordNumber;
};

struct AttributeHeader {
	uint32_t attributeType;
	uint32_t length;
	uint8_t	 nonResident;
	uint8_t	 nameLength;
	uint16_t nameOffset;
	uint16_t flags;
	uint16_t attributeID;
};

struct ResidentAttributeHeader : AttributeHeader {
	uint32_t attributeLength;
	uint16_t attributeOffset;
	uint8_t	 indexed;
	uint8_t	 unused;
};

struct FileNameAttributeHeader : ResidentAttributeHeader {
	uint64_t parentRecordNumber : 48;
	uint64_t sequenceNumber	 : 16;
	uint64_t creationTime;
	uint64_t modificationTime;
	uint64_t metadataModificationTime;
	uint64_t readTime;
	uint64_t allocatedSize;
	uint64_t realSize;
	uint32_t flags;
	uint32_t repase;
	uint8_t	 fileNameLength;
	uint8_t	 namespaceType;
	wchar_t	 fileName[1];
};

struct NonResidentAttributeHeader : AttributeHeader {
	uint64_t firstCluster;
	uint64_t lastCluster;
	uint16_t dataRunsOffset;
	uint16_t compressionUnit;
	uint32_t unused;
	uint64_t attributeAllocated;
	uint64_t attributeSize;
	uint64_t streamDataSize;
};

struct RunHeader {
	uint8_t	 lengthFieldBytes : 4;
	uint8_t	 offsetFieldBytes : 4;
};
#pragma pack(pop)

struct File {
	uint64_t parent;
	char	*name;
	bool	 isChromeInstallation;
};

File *files;

DWORD bytesAccessed;
HANDLE drive;

BootSector bootSector;

#define MFT_FILE_SIZE (1024)
uint8_t mftFile[MFT_FILE_SIZE];

#define MFT_FILES_PER_BUFFER (65536)
uint8_t mftBuffer[MFT_FILES_PER_BUFFER * MFT_FILE_SIZE];

char *DuplicateName(wchar_t *name, size_t nameLength) {
	static char *allocationBlock = nullptr;
	static size_t bytesRemaining = 0;

	size_t bytesNeeded = WideCharToMultiByte(CP_UTF8, 0, name, nameLength, NULL, 0, NULL, NULL) + 1;

	if (bytesRemaining < bytesNeeded) {
		allocationBlock = (char *) malloc((bytesRemaining = 16 * 1024 * 1024));
	}

	char *buffer = allocationBlock;
	buffer[bytesNeeded - 1] = 0;
	WideCharToMultiByte(CP_UTF8, 0, name, nameLength, allocationBlock, bytesNeeded, NULL, NULL);

	bytesRemaining -= bytesNeeded;
	allocationBlock += bytesNeeded;

	return buffer;
}

void Read(void *buffer, uint64_t from, uint64_t count) {
	LONG high = from >> 32;
	SetFilePointer(drive, from & 0xFFFFFFFF, &high, FILE_BEGIN);
	ReadFile(drive, buffer, count, &bytesAccessed, NULL);
	assert(bytesAccessed == count);
}

intptr_t GetCount() {
	drive = CreateFile("\\\\.\\C:", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	
	if (drive == INVALID_HANDLE_VALUE) {
		return -1;
	}

	Read(&bootSector, 0, 512);

	uint64_t bytesPerCluster = bootSector.bytesPerSector * bootSector.sectorsPerCluster;

	Read(&mftFile, bootSector.mftStart * bytesPerCluster, MFT_FILE_SIZE);

	FileRecordHeader *fileRecord = (FileRecordHeader *) mftFile;
	AttributeHeader *attribute = (AttributeHeader *) (mftFile + fileRecord->firstAttributeOffset);
	NonResidentAttributeHeader *dataAttribute = nullptr;
	uint64_t approximateRecordCount = 0;
	assert(fileRecord->magic == 0x454C4946);

	while (true) {
		if (attribute->attributeType == 0x80) {
			dataAttribute = (NonResidentAttributeHeader *) attribute;
		} else if (attribute->attributeType == 0xB0) {
			approximateRecordCount = ((NonResidentAttributeHeader *) attribute)->attributeSize * 8;
		} else if (attribute->attributeType == 0xFFFFFFFF) {
			break;
		}

		attribute = (AttributeHeader *) ((uint8_t *) attribute + attribute->length);
	}

	assert(dataAttribute);
	RunHeader *dataRun = (RunHeader *) ((uint8_t *) dataAttribute + dataAttribute->dataRunsOffset);
	uint64_t clusterNumber = 0, recordsProcessed = 0;

	while (((uint8_t *) dataRun - (uint8_t *) dataAttribute) < dataAttribute->length && dataRun->lengthFieldBytes) {
		uint64_t length = 0, offset = 0;

		for (int i = 0; i < dataRun->lengthFieldBytes; i++) {
			length |= (uint64_t) (((uint8_t *) dataRun)[1 + i]) << (i * 8);
		}

		for (int i = 0; i < dataRun->offsetFieldBytes; i++) {
			offset |= (uint64_t) (((uint8_t *) dataRun)[1 + dataRun->lengthFieldBytes + i]) << (i * 8);
		}

		if (offset & ((uint64_t) 1 << (dataRun->offsetFieldBytes * 8 - 1))) {
			for (int i = dataRun->offsetFieldBytes; i < 8; i++) {
				offset |= (uint64_t) 0xFF << (i * 8);
			}
		}

		clusterNumber += offset;
		dataRun = (RunHeader *) ((uint8_t *) dataRun + 1 + dataRun->lengthFieldBytes + dataRun->offsetFieldBytes);

		uint64_t filesRemaining = length * bytesPerCluster / MFT_FILE_SIZE;
		uint64_t positionInBlock = 0;

		while (filesRemaining) {
			uint64_t filesToLoad = MFT_FILES_PER_BUFFER;
			if (filesRemaining < MFT_FILES_PER_BUFFER) filesToLoad = filesRemaining;
			Read(&mftBuffer, clusterNumber * bytesPerCluster + positionInBlock, filesToLoad * MFT_FILE_SIZE);
			positionInBlock += filesToLoad * MFT_FILE_SIZE;
			filesRemaining -= filesToLoad;

			for (int i = 0; i < filesToLoad; i++) {
				// Even on an SSD, processing the file records takes only a fraction of the time to read the data,
				// so there's not much point in multithreading this.

				FileRecordHeader *fileRecord = (FileRecordHeader *) (mftBuffer + MFT_FILE_SIZE * i);
				recordsProcessed++;

				if (!fileRecord->inUse) continue;

				AttributeHeader *attribute = (AttributeHeader *) ((uint8_t *) fileRecord + fileRecord->firstAttributeOffset);
				assert(fileRecord->magic == 0x454C4946);

				while ((uint8_t *) attribute - (uint8_t *) fileRecord < MFT_FILE_SIZE) {
					if (attribute->attributeType == 0x30) {
						FileNameAttributeHeader *fileNameAttribute = (FileNameAttributeHeader *) attribute;

						if (fileNameAttribute->namespaceType != 2 && !fileNameAttribute->nonResident) {
							File file = {};
							file.parent = fileNameAttribute->parentRecordNumber;
							file.name = DuplicateName(fileNameAttribute->fileName, fileNameAttribute->fileNameLength);

							uint64_t oldLength = arrlenu(files);

							if (fileRecord->recordNumber >= oldLength) {
								arrsetlen(files, fileRecord->recordNumber + 1);
								memset(files + oldLength, 0, sizeof(File) * (fileRecord->recordNumber - oldLength));
							}

							files[fileRecord->recordNumber] = file;
						}
					} else if (attribute->attributeType == 0xFFFFFFFF) {
						break;
					}

					attribute = (AttributeHeader *) ((uint8_t *) attribute + attribute->length);
				}
			}
		}
	}
	
	uintptr_t chromeInstallationCount = 0;
	
	for (uintptr_t i = 0; i < arrlenu(files); i++) {
		if (files[i].name && strstr(files[i].name, "_percent.pak")) {
			bool *isChromeInstallation = &files[files[i].parent].isChromeInstallation;
			
			if (!(*isChromeInstallation)) {
				chromeInstallationCount++;
				*isChromeInstallation = true;
			}
		}
	}

	return chromeInstallationCount;
}

DWORD WINAPI WorkerThread(void *) {
	countResult = GetCount();
	SendMessage(root, WM_APP + 1, 0, 0);
	return 0;
}

typedef HRESULT (*GetDpiForMonitorType)(HMONITOR hmonitor, MONITOR_DPI_TYPE dpiType, UINT *dpiX, UINT *dpiY);
typedef BOOL (*SetProcessDpiAwarenessContextType)(DPI_AWARENESS_CONTEXT value);

LRESULT CALLBACK WindowProcedure(HWND window, UINT message, WPARAM wParam, LPARAM lParam) {
	if (message == WM_DESTROY) {
		PostQuitMessage(0);
	} else if (message == WM_APP + 1) {
		DestroyWindow(progress);
		
		if (countResult == -1) {
			SetWindowText(label2, "Could not access the C: drive! Maybe you forgot to run the program as administrator?");
		} else {
			char buffer[256];
			snprintf(buffer, 256, "You have %lld Chrome installations!", countResult);
			SetWindowText(label2, buffer);
		}
	} else if (message == WM_DPICHANGED) {
		RECT *newBounds = (RECT *) lParam;
		MoveWindow(window, newBounds->left, newBounds->top, 
			newBounds->right - newBounds->left, newBounds->bottom - newBounds->top, TRUE);
	} else {
		return DefWindowProc(window, message, wParam, lParam);
	}

	return 0;
}

int __stdcall WinMain(HINSTANCE instance, HINSTANCE previousInstance, char *commandLine, int commandShow) {
	OSVERSIONINFOEXW version = { sizeof(version) };
	((LONG (*)(PRTL_OSVERSIONINFOEXW)) GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion"))(&version);
	
	HMODULE shcore = NULL;

	if (version.dwMajorVersion >= 10) {
		shcore = LoadLibrary("shcore.dll");
		SetProcessDpiAwarenessContextType setProcessDpiAwarenessContext 
			= (SetProcessDpiAwarenessContextType) GetProcAddress(LoadLibrary("user32.dll"), "SetProcessDpiAwarenessContext");
		setProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
	} else {
		SetProcessDPIAware();
	}

	CoInitialize(NULL);

	INITCOMMONCONTROLSEX icc = {};
	icc.dwSize = sizeof(INITCOMMONCONTROLSEX);
	icc.dwICC = ICC_WIN95_CLASSES;
	InitCommonControlsEx(&icc);

	WNDCLASSEX windowClass = {};
	windowClass.cbSize = sizeof(WNDCLASSEX);
	windowClass.cbWndExtra = sizeof(LONG_PTR) * 2 /* font, dpiScale */;
	windowClass.style = CS_HREDRAW | CS_VREDRAW;
	windowClass.lpfnWndProc = WindowProcedure;
	windowClass.hInstance = instance;
	windowClass.lpszClassName = "frame";
	windowClass.hCursor = LoadCursor(NULL, IDC_ARROW);
	windowClass.hbrBackground = (HBRUSH) COLOR_WINDOW;
	RegisterClassEx(&windowClass);
	
	DWORD windowStyle = WS_CLIPSIBLINGS | WS_MINIMIZEBOX | WS_SYSMENU;
	root = CreateWindowEx(0, "frame", "How many Chrome installations?", 
		windowStyle, CW_USEDEFAULT, CW_USEDEFAULT, 800, 600, NULL, NULL, instance, NULL);
	ShowWindow(root, commandShow);
	RECT windowBounds;
	GetClientRect(root, &windowBounds);
	
	CreateThread(0, 0, WorkerThread, 0, 0, 0);
	
	HFONT bigFont;
	int dpi;
	
	{
		if (shcore) {
			HMONITOR monitor = MonitorFromWindow(root, MONITOR_DEFAULTTOPRIMARY);
			UINT x, y;
			GetDpiForMonitorType getDpiForMonitor = (GetDpiForMonitorType) GetProcAddress(shcore, "GetDpiForMonitor");
			getDpiForMonitor(monitor, MDT_EFFECTIVE_DPI, &x, &y);
			dpi = y;
		} else {
			HDC screen = GetDC(NULL);
			dpi = GetDeviceCaps(screen, LOGPIXELSY);
			ReleaseDC(NULL, screen);
		}
	
		NONCLIENTMETRICSW metrics = {};
		metrics.cbSize = sizeof(NONCLIENTMETRICSW);
		SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(metrics), &metrics, 0);
		metrics.lfMessageFont.lfHeight = -(15 * dpi) / 72;
		bigFont = CreateFontIndirectW(&metrics.lfMessageFont);
	}
	
	label1 = CreateWindow("static", "How many Chrome installations are on your C: drive?", 
		WS_CHILD | WS_VISIBLE | SS_CENTER, 20, 20 * dpi / 96, windowBounds.right - 40, 60 * dpi / 96, root, 0, 0, 0);
	SendMessage(label1, WM_SETFONT, (WPARAM) bigFont, (LPARAM) TRUE);
	progress = CreateWindow(PROGRESS_CLASS, "", WS_CHILD | WS_VISIBLE | PBS_MARQUEE,
		windowBounds.right / 2 - 150 * dpi / 96, 90 * dpi / 96, 300 * dpi / 96, 25 * dpi / 96, root, 0, 0, 0);
	SendMessage(progress, PBM_SETMARQUEE, TRUE, 16);
	label2 = CreateWindow("static", "Please wait...", 
		WS_CHILD | WS_VISIBLE | SS_CENTER, 20, 145 * dpi / 96, windowBounds.right - 40, 60 * dpi / 96, root, 0, 0, 0);
	SendMessage(label2, WM_SETFONT, (WPARAM) bigFont, (LPARAM) TRUE);

	MSG message;

	while (GetMessage(&message, NULL, 0, 0) > 0) {
		TranslateMessage(&message);
		DispatchMessage(&message);
	}

	return message.wParam;
}