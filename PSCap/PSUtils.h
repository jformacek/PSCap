using namespace System;
using namespace System::Management::Automation;
using namespace System::IO;
using namespace System::Resources;
using namespace System::Reflection;
using namespace System::Collections::Generic;

namespace PSCap {
	public ref class PSUtils
	{
	public:
		static DateTime^ GetStampAsDateTime(LPSYSTEMTIME lpST)
		{
			FILETIME ft;
			ULARGE_INTEGER *pLI = (ULARGE_INTEGER*) &ft;

			if (lpST == NULL)
				throw gcnew ArgumentException("GetStampAsInt64");

			if (!SystemTimeToFileTime(lpST, &ft))
				throw gcnew System::ComponentModel::Win32Exception(::GetLastError(), "SystemTimeToFileTime");

			return DateTime::FromFileTimeUtc(pLI->QuadPart);
		}

		static CaptureFileInfo^ GetCaptureInfo(String^ fileName)
		{
			HANDLE inStream = INVALID_HANDLE_VALUE;
			LPCAPFILEHEADER lpFileHeader = nullptr;
			pin_ptr<const wchar_t> inFile;
			DWORD dwBytesRead;
			CaptureFileInfo ^output = gcnew CaptureFileInfo(fileName);
			try {
				//capture file header handling
				LPCAPFILEHEADER lpFileHeader = (LPCAPFILEHEADER) malloc(sizeof(CAPFILEHEADER));

				inFile = PtrToStringChars(fileName);
				inStream = ::CreateFile(inFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
				if (inStream == INVALID_HANDLE_VALUE)
					throw gcnew System::ComponentModel::Win32Exception(::GetLastError(), "CreateFile");
				if (!::ReadFile(inStream, lpFileHeader, sizeof(CAPFILEHEADER), &dwBytesRead, NULL))
					throw gcnew System::ComponentModel::Win32Exception(::GetLastError(), "ReadFile");

				//capture header processing
				output->Timestamp = PSUtils::GetStampAsDateTime(&(lpFileHeader->TimeStamp));
				if (lpFileHeader->BCDVerMajor < 2 || (lpFileHeader->BCDVerMajor == 2 && lpFileHeader->BCDVerMinor == 0))
					output->IsOldFormat = true;
				output->Frames = lpFileHeader->FrameTableLength / sizeof(DWORD);
				output->FrameTableOffset = lpFileHeader->FrameTableOffset;
			}
			finally {
				if (lpFileHeader != nullptr)
					free(lpFileHeader);
				if (inStream != INVALID_HANDLE_VALUE)
					CloseHandle(inStream);
			}
			return output;
		}

		static DateTime^ CutTimestamp(DateTime ^Timestamp, UInt32 IntervalSecs)
		{
			UInt32 sec = Timestamp->Second;
			UInt32 min = Timestamp->Minute;

			//display in whole minutes if interval > minute
			if (IntervalSecs>59)
				sec = 0;
			//display in whole hours if interval > hour
			if (IntervalSecs > 3599)
				min = 0;

			return gcnew DateTime(Timestamp->Year, Timestamp->Month, Timestamp->Day, Timestamp->Hour, min, sec);
		}

		static void SyncWorkingDirectory()
		{
			//sync Powershell and .NET current working directory, so as relative path work as expected
			SessionState ^ss = gcnew SessionState();
			Directory::SetCurrentDirectory(ss->Path->CurrentFileSystemLocation->Path);
		}

	};
}