#pragma once

#define MICROSECONDS_IN_SECOND	1000000
//workaround for bug in netmon - invalid timestamp for some frames
//bug caused the frame processor to get into almost infinite loop
//when frame offset between current and previous frame is bigger than this, timestamp is considered invalid and is ignored
//1 hour = 3600000000 microseconds
//this means that there must be at least 1 frame an hour in capture so as it was correctly processed
#define MAX_TIMESTAMP_DIFFERENCE 3600000000
namespace PSCap
{
	typedef struct _FRAMEHEADER
	{
		unsigned __int64 TimeStamp; 
		DWORD FrameLength;
		DWORD BytesAvailable;
	} FRAMEHEADER, *LPFRAMEHEADER;

	typedef struct _CAPFILEHEADER
	{
		DWORD Signature;
		BYTE BCDVerMinor;
		BYTE BCDVerMajor;
		WORD MacType;
		SYSTEMTIME TimeStamp;
		DWORD FrameTableOffset;
		DWORD FrameTableLength;
		DWORD UserDataOffset;
		DWORD UserDataLength;
		DWORD CommentDataOffset;
		DWORD CommentDataLength;
		DWORD StatisticsOffset;
		DWORD StatisticsLength;
		DWORD NetworkInfoOffset;
		DWORD NetworkInfoLength;
		DWORD ConversationStatsOffset;
		DWORD ConversationStatsLength;
	} CAPFILEHEADER, *LPCAPFILEHEADER;
}