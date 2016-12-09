// precompile.h
// Author: ¡ŒÃÌ(Tankle L.)
// Date: December 8th, 2016

#include <fstream>
#include <iostream>
#include <vector>
#include <string>
#include <unordered_map>

#include <time.h>
#include <guiddef.h>
#include <comdef.h>

#include "../../inc/sha2-lib/sha2.h"


// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// !!!        DON NOT USE 32-BITs MOD SO FAR        !!!
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!


#if defined(_DEBUG)	// Debug
#	if !defined(_x64)	// 32-bits
#		pragma comment(lib, "../../bin/sha2-lib_d.lib")
#	else				// 64-bits
#		pragma comment(lib, "../../bin/sha2-lib_x64_d.lib")
#	endif
#else				// Release
#	if !defined(_x64)	// 32-bits
#		pragma comment(lib, "../../bin/sha2-lib.lib")
#	else				// 64-bits
#		pragma comment(lib, "../../bin/sha2-lib_x64.lib")
#	endif
#endif