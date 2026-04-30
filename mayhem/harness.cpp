// Mayhem fuzzing harness for mfcmapi binary parsing utilities.
//
// The upstream mfcmapi project is a Windows MFC/MAPI application that cannot
// be built natively on Linux. To exercise the binary-parsing logic in
// core/smartview/block/binaryParser.h on Mayhem's Linux runners, this harness
// provides a self-contained minimal Win32 type shim and re-implements the
// binaryParser class verbatim from upstream so it can be built with a
// standard Linux clang + libFuzzer toolchain.
//
// This is intentionally a narrow harness: it stress-tests the offset/cap/
// bounds-tracking machinery used by every SmartView parser. Crashes here
// indicate bugs that would manifest in any of the higher-level parsers
// (EntryIdStruct, GlobalObjectId, RuleAction, etc.) that build on top of
// binaryParser.

#include <cstddef>
#include <cstdint>
#include <stack>
#include <vector>

// ---------------------------------------------------------------------------
// Minimal Win32 type shim. Mirrors what mapistub/include/MAPIWin.h provides
// when targeting Windows; sufficient for binaryParser.h to compile.
// ---------------------------------------------------------------------------
using BYTE = unsigned char;
using WORD = unsigned short;
using DWORD = unsigned int;
using ULONG = unsigned int;
using LONG = int;
using LARGE_INTEGER = long long;
using GUID = struct { uint32_t a; uint16_t b, c; uint8_t d[8]; };

#ifndef _In_count_
#define _In_count_(x)
#endif
#ifndef _In_
#define _In_
#endif

// ---------------------------------------------------------------------------
// Verbatim copy of core/smartview/block/binaryParser.h (upstream HEAD).
// Keep this synchronized with upstream — diff against the source on update.
// ---------------------------------------------------------------------------
namespace smartview
{
	class binaryParser
	{
	public:
		binaryParser() = default;
		binaryParser(size_t cb, _In_count_(cb) const BYTE* _bin)
		{
			bin = _bin && cb ? std::vector<BYTE>(_bin, _bin + cb) : std::vector<BYTE>{};
			size = bin.size();
		}
		binaryParser(const std::vector<BYTE>& _bin)
		{
			bin = _bin;
			size = bin.size();
		}

		binaryParser(const binaryParser&) = delete;
		binaryParser& operator=(const binaryParser&) = delete;

		bool empty() const noexcept { return offset == size; }
		void advance(size_t cb) noexcept { offset += cb; }
		void rewind() noexcept { offset = 0; }
		size_t getOffset() const noexcept { return offset; }
		void setOffset(size_t _offset) noexcept { offset = _offset; }
		const BYTE* getAddress() const noexcept { return bin.data() + offset; }
		void setCap(size_t cap)
		{
			sizes.push(size);
			if (cap != 0 && offset + cap < size)
			{
				size = offset + cap;
			}
		}

		void clearCap()
		{
			if (sizes.empty())
			{
				size = bin.size();
			}
			else
			{
				size = sizes.top();
				sizes.pop();
			}
		}

		size_t getSize() const noexcept { return offset > size ? 0 : size - offset; }
		bool checkSize(size_t cb) const noexcept { return cb <= getSize(); }

	private:
		std::vector<BYTE> bin;
		size_t offset{};
		size_t size{};
		std::stack<size_t> sizes;
	};
} // namespace smartview

// ---------------------------------------------------------------------------
// Templated read helper (modeled after blockT<T>::parse in upstream
// core/smartview/block/blockT.h). Reads a fixed-size POD from the parser
// and advances the offset. Returns a default-constructed value if the
// remaining buffer is too small.
// ---------------------------------------------------------------------------
template <typename T>
static T parseOne(smartview::binaryParser& parser)
{
	T value{};
	if (parser.checkSize(sizeof(T)))
	{
		const BYTE* p = parser.getAddress();
		// Use memcpy to avoid unaligned-load undefined behavior.
		__builtin_memcpy(&value, p, sizeof(T));
		parser.advance(sizeof(T));
	}
	return value;
}

// ---------------------------------------------------------------------------
// LibFuzzer entry point.
// Drives the binaryParser through a sequence of parse/cap/rewind operations
// using bytes from the input as a control stream.
// ---------------------------------------------------------------------------
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	if (size < 1) return 0;

	const uint8_t op = data[0];
	const uint8_t* payload = data + 1;
	const size_t payload_size = size - 1;

	smartview::binaryParser parser(payload_size, payload);

	// Replay a small program of parser operations selected by the input.
	// Bound the loop to keep iterations fast.
	for (size_t i = 0; i < payload_size && i < 256; ++i)
	{
		switch ((op + i) % 10)
		{
			case 0: (void) parseOne<uint8_t>(parser); break;
			case 1: (void) parseOne<uint16_t>(parser); break;
			case 2: (void) parseOne<uint32_t>(parser); break;
			case 3: (void) parseOne<uint64_t>(parser); break;
			case 4: parser.advance(payload[i % payload_size] & 0x0F); break;
			case 5: parser.setCap(payload[i % payload_size]); break;
			case 6: parser.clearCap(); break;
			case 7: (void) parser.getSize(); break;
			case 8: (void) parser.empty(); break;
			case 9: parser.rewind(); break;
		}
	}

	return 0;
}
