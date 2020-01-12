using namespace System;
using namespace System::Management::Automation;
using namespace System::IO;
using namespace System::Resources;
using namespace System::Reflection;
using namespace System::Collections::Generic;

namespace PSCap {

	public ref class CaptureFileInfo
	{
	public:
		String ^Name;
		bool IsOldFormat;
		DateTime ^Timestamp;
		UInt32 Frames;
		UInt32 FrameTableOffset;

		CaptureFileInfo(String^ Name)
		{
			this->Name = Name;
		}
	};

	public ref class CaptureIntervalStats
	{
	public:
		DateTime ^Timestamp;
		UInt32 Bytes;
		UInt32 Frames;
		UInt32 AvgBitrate;
		UInt32 AvgFrameSize;
	};

	union ipv4 {
		Byte b[4];
		UInt32 i;
	};

	public ref class CaptureP2PStats {
	public:
		String ^Source;
		String ^Destination;
		UInt32 Frames;
		UInt32 Bytes;
		UInt32 AvgFrameSize;

		CaptureP2PStats(UInt32 source, UInt32 destination) {
			Source = NumToStr(source);
			Destination = NumToStr(destination);
		}
	protected:
		String^ NumToStr(UInt32 num) {
			ipv4 ip;
			ip.i = num;

			System::Text::StringBuilder ^sb = gcnew System::Text::StringBuilder();
			sb->Append(ip.b[0]);
			sb->Append(".");
			sb->Append(ip.b[1]);
			sb->Append(".");
			sb->Append(ip.b[2]);
			sb->Append(".");
			sb->Append(ip.b[3]);
			return sb->ToString();
		}
	};
}
