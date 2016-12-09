// datatypes.h
// Author: 廖添(Tankle L.)
// Date: October 1st, 2016

#if !defined(DATATYPES_H)
#define DATATYPES_H

namespace Enco
{
	struct guid_hash
	{
		unsigned int operator()(const GUID& guid) const
		{
			return ((guid.Data1 ^ ((guid.Data2 << 0x10) | \
				((unsigned short)guid.Data3))) ^ ((guid.Data4[2] << 0x18) | guid.Data4[7]));
		}
	};

	struct guid_equal
	{
		bool operator()(const GUID& guid1, const GUID& guid2)
		{
			if (guid1.Data1 == guid2.Data1 &&
				guid1.Data2 == guid2.Data2 &&
				guid1.Data3 == guid2.Data3 &&
				guid1.Data4[0] == guid2.Data4[0] &&
				guid1.Data4[1] == guid2.Data4[1] &&
				guid1.Data4[2] == guid2.Data4[2] &&
				guid1.Data4[3] == guid2.Data4[3] &&
				guid1.Data4[4] == guid2.Data4[4] &&
				guid1.Data4[5] == guid2.Data4[5] &&
				guid1.Data4[6] == guid2.Data4[6] &&
				guid1.Data4[7] == guid2.Data4[7])
				return true;
			return false;
		}
	};

	typedef unsigned char		byte;
	typedef unsigned __int32	uint32;
	typedef unsigned __int64	uint64;
	typedef __int32				int32;
}

#endif