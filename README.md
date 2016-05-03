# DynamicLoad
A C++ class to load dynamically APIs from PEB.
Credits to: Topher Timzen (https://www.tophertimzen.com/blog/shellcodeTechniquesCPP/)

Usage:
```
#include "DynamicLoad.hpp"

int main()
{
    DynamicLoad::fMessageBoxA(0, "Message", "Title", 0);
    return 0;
}
```
