// PSCap.h

#pragma once

using namespace System;
using namespace System::Management::Automation;
using namespace System::IO;
using namespace System::Resources;
using namespace System::Reflection;
using namespace System::Collections::Generic;


namespace PSCap {
	[CmdletAttribute("Get", "CaptureFileInfo")]
	public ref class GetCaptureInfo:public Cmdlet
	{
	public:
		[Parameter(Mandatory=true, Position=0, ValueFromPipeline=true)]
		property String ^CaptureFile;

		virtual void BeginProcessing() override
		{
			PSUtils::SyncWorkingDirectory();
		}

		virtual void ProcessRecord() override
		{
			if(!File::Exists(CaptureFile))
				throw gcnew FileNotFoundException();

			WriteObject(PSUtils::GetCaptureInfo(CaptureFile));
		}
	};

	[CmdletAttribute("Get", "CaptureBandwidthStats")]
	public ref class GetCaptureBandwidthStats:public Cmdlet
	{
	protected:
		String ^_template_Activity;
		String ^_template_StatusDescription;
	public:
		[Parameter(Mandatory=true, Position=0, ValueFromPipeline=true)]
		property String ^CaptureFile;
		[Parameter(Mandatory=true, Position=1)]
		property UInt32 Interval;
		[Parameter()]
		property SwitchParameter ShowProgress;


		virtual void BeginProcessing() override
		{
			//sync Powershell and .NET current working directory, so as relative path work as expected
			PSUtils::SyncWorkingDirectory();

			//load progress reporting templates
			ResourceManager ^rm=gcnew ResourceManager("PSCap.Messages",Assembly::GetExecutingAssembly());
			_template_Activity=rm->GetString("IDS_TEMPLATE_ACTIVITY");
			_template_StatusDescription=rm->GetString("IDS_TEMPLATE_STATUS_DESCRIPTION");
		}

		virtual void ProcessRecord() override
		{
			if(!File::Exists(CaptureFile))
				throw gcnew FileNotFoundException();
			if(Interval == 0)
				throw gcnew ArgumentException("Interval");
			CaptureFileInfo^ ci=PSUtils::GetCaptureInfo(CaptureFile);
			
			//handle for reading the capture file
			HANDLE inStream=INVALID_HANDLE_VALUE;
			//pointer to frametable in memory. To speed up processing, we read complete frame table from capture file to memory
			LPDWORD frameTable=nullptr;
			ULONG frameSize;
			//timestamp of each frame. Retrieved from frame metadata
			UInt64 frameTimestamp;
			//progress tracing;
			UInt32 progressStep; 
			UInt32 progressMark;
			try {
				//get capture timestamp respecting time cutting rules
				UInt64 captureTimestamp=PSUtils::CutTimestamp(ci->Timestamp,Interval)->ToFileTimeUtc();

				//offset from cut capture timestamp to first frame
				UInt64 nOffset=ci->Timestamp->ToFileTimeUtc() - captureTimestamp;
				
				//tracker of intervals
				DWORD dwCurrentInterval=1;
				
				//interval length in ticks
				UInt64 intervalLength=(UInt64)(Interval) * (UInt64)(MICROSECONDS_IN_SECOND * 10);
				
				//number of frames in capture file we want to process
				UInt32 frameCount=ci->Frames;
				
				//number of frames processed after we update progress
				progressStep=ci->Frames / 100;
				progressMark=progressStep;

				//Netmon 2.x stores capture file info as a last frame; we do not want process it
				if(ci->IsOldFormat)
					frameCount--;

				//allocate memory for frame table
				UInt32 frameTableLength=ci->Frames*sizeof(DWORD);
				frameTable=(LPDWORD)malloc(frameTableLength);
				if(frameTable==nullptr)
					throw gcnew OutOfMemoryException("AllocFrameTable");

				//helper for ::ReadFile() API
				DWORD dwBytesRead;

				//open the capture file
				pin_ptr<const wchar_t> inFile=PtrToStringChars(ci->Name);
				inStream=::CreateFile(inFile,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
				if(inStream==INVALID_HANDLE_VALUE)
					throw gcnew System::ComponentModel::Win32Exception(::GetLastError(),"CreateFile");

				//read frame table into memory
				LPDWORD nextTableEntry=frameTable;
				::SetFilePointer(inStream,ci->FrameTableOffset,NULL,FILE_BEGIN);
				::ReadFile(inStream,frameTable,frameTableLength,&dwBytesRead,NULL);
				if(dwBytesRead!=frameTableLength)
					throw gcnew Exception("Was not able to read complete frame table");

				//end of current interval
				UInt64 nLimit=captureTimestamp + intervalLength;

				//pointer to buffer for frame metadata
				LPFRAMEHEADER lpHdr=nullptr;
				//pointer for raw frame data
				//TODO: filtering based on IP address, port, protocol
				LPBYTE rawFrameData=nullptr;

				//try eliminate netmon 3.x special frames - stored as first frames in file
				UInt64 timestampScalingFactor=0;
				bool isNetmonFrame=true;
				ULONG numNetmonFrames=0;
				ULONG frameOffset=0L;
				do {
					::SetFilePointer(inStream,*nextTableEntry,NULL,FILE_BEGIN);
					lpHdr=(LPFRAMEHEADER)malloc(sizeof(FRAMEHEADER));
					::ReadFile(inStream,lpHdr,sizeof(FRAMEHEADER),&dwBytesRead,NULL);

					//skip frame data to get to MAC type
					::SetFilePointer(inStream, lpHdr->BytesAvailable, NULL, FILE_CURRENT);
					//get mac type
					WORD frameMac;
					::ReadFile(inStream,&frameMac,sizeof(WORD),&dwBytesRead,NULL);
					if(frameMac<0xFFFB) {
						//not a netmon special frame
						isNetmonFrame=false;
					}
					else {
						nextTableEntry++;
						numNetmonFrames++;
					}
					free(lpHdr);

				} while (isNetmonFrame==true);

				//process frames
				bool _isAtStart=true;
				//helper for workaround for bug in netmon - invalid timespamp for some frames
				unsigned __int64 prevTimeStamp=0;
				//this is outpput data
				CaptureIntervalStats^ cis=gcnew CaptureIntervalStats();
				for(UInt32 i=numNetmonFrames;i<frameCount;i++) {
					if(ShowProgress && i > progressMark) {
						ProgressRecord ^pr=gcnew ProgressRecord(
							0,
							String::Format(
								_template_Activity,
								CaptureFile
							),
							String::Format(
								_template_StatusDescription,
								i
							)
						);
						pr->PercentComplete=progressMark*100/frameCount;
						pr->RecordType=ProgressRecordType::Processing;
						WriteProgress(pr);
						progressMark+=progressStep;
					}
					//get current frame in capture file
					::SetFilePointer(inStream,*nextTableEntry,NULL,FILE_BEGIN);
					nextTableEntry++;
					//read frame metadata
					lpHdr=(LPFRAMEHEADER)malloc(sizeof(FRAMEHEADER));
					::ReadFile(inStream,lpHdr,sizeof(FRAMEHEADER),&dwBytesRead,NULL);

					//TODO: filtering based on IP address, port, protocol
					//we will need to process raw frame data then - this is how to read it
					//rawFrameData=(LPBYTE)malloc(lpHdr->BytesAvailable);
					//::ReadFile(inStream,rawFrameData,lpHdr->BytesAvailable,&dwBytesRead,NULL);

					//get info about frame
					frameSize=lpHdr->FrameLength;
					//get frame timestamp - offset in microseconds from the capture timestamp
					//workaround for bug in netmon
					if(lpHdr->TimeStamp - prevTimeStamp < (unsigned __int64) MAX_TIMESTAMP_DIFFERENCE) { 
						//everything OK
						frameTimestamp=captureTimestamp + nOffset + (lpHdr->TimeStamp * 10);
						prevTimeStamp=lpHdr->TimeStamp;
					} else {
						//probably invalid timestamp
						//just ignore it and use timestamp of previous frame
					}
					//this loop also handles intervals with no frames
					while(frameTimestamp > nLimit) {
						cis->Timestamp=DateTime::FromFileTimeUtc(captureTimestamp+((UInt64)dwCurrentInterval*intervalLength));
						cis->AvgBitrate=cis->Bytes * 8 / Interval;
						if(cis->Frames > 0)
							cis->AvgFrameSize=cis->Bytes / cis->Frames;
						if(!_isAtStart) {
							//we do not want leading empty results in output
							WriteObject(cis);
						}
						//compute new limit
						dwCurrentInterval++;
						nLimit+=intervalLength;
						cis=gcnew CaptureIntervalStats();
					}
					_isAtStart=false;
					//else sum frame sizes
					cis->Bytes+=frameSize;
					//also sum frames
					cis->Frames++;

					//prepare for the next frame
					free(lpHdr);
					//TODO: filtering based on IP address, port, protocol
					//free(rawFrameData);
				}	//for
				//write last data
				cis->Timestamp=DateTime::FromFileTimeUtc(captureTimestamp+((UInt64)dwCurrentInterval*intervalLength));
				cis->AvgBitrate=cis->Bytes * 8 / Interval;
				if(cis->Frames > 0)
					cis->AvgFrameSize=cis->Bytes / cis->Frames;
				WriteObject(cis);
				if(ShowProgress) {
					ProgressRecord ^pr=gcnew ProgressRecord(
						0,
							String::Format(
								_template_Activity,
								CaptureFile
							),
							String::Format(
								_template_StatusDescription,
								frameCount
							)

					);
					pr->RecordType=ProgressRecordType::Completed;
					WriteProgress(pr);
				}
			}
			finally {
				if(inStream != INVALID_HANDLE_VALUE)
					CloseHandle(inStream);
				if(frameTable != nullptr)
					free(frameTable);
			}
		}
	};

	[CmdletAttribute("Get", "CaptureP2PStats")]
	public ref class GetCaptureP2PStats :public Cmdlet
	{
	protected:
		String ^_template_Activity;
		String ^_template_StatusDescription;
		Dictionary<UInt32, Dictionary<UInt32, CaptureP2PStats^>^> ^data = gcnew Dictionary<UInt32, Dictionary<UInt32, CaptureP2PStats^>^>();
	public:
		[Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true)]
		property String ^CaptureFile;
		[Parameter()]
		property SwitchParameter ShowProgress;


		virtual void BeginProcessing() override
		{
			//sync Powershell and .NET current working directory, so as relative path work as expected
			PSUtils::SyncWorkingDirectory();

			//load progress reporting templates
			ResourceManager ^rm = gcnew ResourceManager("PSCap.Messages", Assembly::GetExecutingAssembly());
			_template_Activity = rm->GetString("IDS_TEMPLATE_ACTIVITY");
			_template_StatusDescription = rm->GetString("IDS_TEMPLATE_STATUS_DESCRIPTION");
		}

		virtual void ProcessRecord() override
		{
			if (!File::Exists(CaptureFile))
				throw gcnew FileNotFoundException();
			CaptureFileInfo^ ci = PSUtils::GetCaptureInfo(CaptureFile);

			//handle for reading the capture file
			HANDLE inStream = INVALID_HANDLE_VALUE;
			//pointer to frametable in memory. To speed up processing, we read complete frame table from capture file to memory
			LPDWORD frameTable = nullptr;
			//progress tracing;
			UInt32 progressStep;
			UInt32 progressMark;
			try {

				//number of frames in capture file we want to process
				UInt32 frameCount = ci->Frames;

				//number of frames processed after we update progress
				progressStep = ci->Frames / 100;
				progressMark = progressStep;

				//Netmon 2.x stores capture file info as a last frame; we do not want process it
				if (ci->IsOldFormat)
					frameCount--;

				//allocate memory for frame table
				UInt32 frameTableLength = ci->Frames*sizeof(DWORD);
				frameTable = (LPDWORD) malloc(frameTableLength);
				if (frameTable == nullptr)
					throw gcnew OutOfMemoryException("AllocFrameTable");

				//helper for ::ReadFile() API
				DWORD dwBytesRead;

				//open the capture file
				pin_ptr<const wchar_t> inFile = PtrToStringChars(ci->Name);
				inStream = ::CreateFile(inFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
				if (inStream == INVALID_HANDLE_VALUE)
					throw gcnew System::ComponentModel::Win32Exception(::GetLastError(), "CreateFile");

				//read frame table into memory
				LPDWORD nextTableEntry = frameTable;
				::SetFilePointer(inStream, ci->FrameTableOffset, NULL, FILE_BEGIN);
				::ReadFile(inStream, frameTable, frameTableLength, &dwBytesRead, NULL);
				if (dwBytesRead != frameTableLength)
					throw gcnew Exception("Was not able to read complete frame table");

				//pointer to buffer for frame metadata
				LPFRAMEHEADER lpHdr = nullptr;
				//pointer for raw frame data
				//TODO: filtering based on IP address, port, protocol
				LPBYTE rawFrameData = nullptr;

				//eliminate netmon 3.x special frames - stored as first frames in file
				bool isNetmonFrame = true;
				ULONG numNetmonFrames = 0;
				ULONG frameOffset = 0L;
				do {
					::SetFilePointer(inStream, *nextTableEntry, NULL, FILE_BEGIN);
					lpHdr = (LPFRAMEHEADER) malloc(sizeof(FRAMEHEADER));
					::ReadFile(inStream, lpHdr, sizeof(FRAMEHEADER), &dwBytesRead, NULL);
					//skip frame data to get to MAC type
					::SetFilePointer(inStream, lpHdr->BytesAvailable, NULL, FILE_CURRENT);
					//get mac type
					WORD frameMac;
					::ReadFile(inStream, &frameMac, sizeof(WORD), &dwBytesRead, NULL);
					if (frameMac<0xFFFB) {
						//not a netmon special frame
						isNetmonFrame = false;
					}
					else {
						nextTableEntry++;
						numNetmonFrames++;
					}
					free(lpHdr);

				} while (isNetmonFrame == true);

				//process frames
				for (UInt32 i = numNetmonFrames; i<frameCount; i++) {
					if (ShowProgress && i > progressMark) {
						ProgressRecord ^pr = gcnew ProgressRecord(
							0,
							String::Format(
							_template_Activity,
							CaptureFile
							),
							String::Format(
							_template_StatusDescription,
							i
							)
						);
						pr->PercentComplete = progressMark * 100 / frameCount;
						pr->RecordType = ProgressRecordType::Processing;
						WriteProgress(pr);
						progressMark += progressStep;
					}
					//get current frame in capture file
					::SetFilePointer(inStream, *nextTableEntry, NULL, FILE_BEGIN);
					nextTableEntry++;
					//read frame metadata
					lpHdr = (LPFRAMEHEADER) malloc(sizeof(FRAMEHEADER));
					::ReadFile(inStream, lpHdr, sizeof(FRAMEHEADER), &dwBytesRead, NULL);

					//TODO: filtering based on IP address, port, protocol and detect ipv4/6 protocol data automatically
					rawFrameData=(LPBYTE)malloc(lpHdr->BytesAvailable);
					::ReadFile(inStream,rawFrameData,lpHdr->BytesAvailable,&dwBytesRead,NULL);
					UInt32 *pSource = (UINT32*)(rawFrameData + 0x1a);
					UInt32 *pDest = (UINT32*) (rawFrameData + 0x1e);

					if (!data->ContainsKey(*pSource)) {
						data->Add(*pSource, gcnew Dictionary<UInt32, CaptureP2PStats^>());
						data[*pSource]->Add(*pDest, gcnew CaptureP2PStats(*pSource, *pDest));
					}
					else {
						if (!data[*pSource]->ContainsKey(*pDest)) {
							data[*pSource]->Add(*pDest, gcnew CaptureP2PStats(*pSource, *pDest));
						}
					}
					Dictionary<UInt32, CaptureP2PStats^> ^pom = data[*pSource];
					pom[*pDest]->Frames++;
					pom[*pDest]->Bytes += lpHdr->FrameLength;

					//prepare for the next frame
					free(lpHdr);
					free(rawFrameData);
				}	//for
				//write last status update
				if (ShowProgress) {
					ProgressRecord ^pr = gcnew ProgressRecord(
						0,
						String::Format(
						_template_Activity,
						CaptureFile
						),
						String::Format(
						_template_StatusDescription,
						frameCount
						)
					);
					pr->RecordType = ProgressRecordType::Completed;
					WriteProgress(pr);
				}

				//write data
				for each (UInt32 source in data->Keys)
				{
					for each(KeyValuePair<UInt32, CaptureP2PStats^> kvp in data[source])
					{
						kvp.Value->AvgFrameSize = kvp.Value->Bytes / kvp.Value->Frames;
						WriteObject(kvp.Value);
					}
				}
			}
			finally {
				if (inStream != INVALID_HANDLE_VALUE)
					CloseHandle(inStream);
				if (frameTable != nullptr)
					free(frameTable);
			}
		}
	};
}
