/* This file implements a custom memory management wrapper around the Windows Heap API functions. This code can be used to allocate, deallocate, and copy blocks of memory. */
#include "memory.h"
#include "api.h"
/* This function is used to allocate a block of memory of size Size. It calls the HeapAlloc function from the Windows API, 
passing the handle to the default heap of the calling process (GetProcessHeap()) and HEAP_ZERO_MEMORY flag that initializes the allocated memory to zero. */
LPVOID
memory::Alloc(SIZE_T Size) {
	return pHeapAlloc(pGetProcessHeap(), HEAP_ZERO_MEMORY, Size);
}

/* Free(LPVOID Memory): This function is used to free the block of memory pointed to by Memory. It calls the HeapFree function from the Windows API, 
passing the handle to the default heap of the calling process (GetProcessHeap()) and the pointer to the memory block that was previously allocated with HeapAlloc. */
VOID
memory::Free(LPVOID Memory) {
	pHeapFree(pGetProcessHeap(), 0, Memory);
}
/* Copy(PVOID pDst, CONST PVOID pSrc, size_t size): This function is used to copy size bytes from the memory location pointed to by pSrc to the memory location pointed to by pDst. 
It first copies the data in wordsize-byte chunks (where wordsize is the size of size_t on the current platform), then copies the remainder byte by byte. */
VOID
memory::Copy(PVOID pDst, CONST PVOID pSrc, size_t size)
{
	void* tmp = pDst;
	size_t wordsize = sizeof(size_t);
	unsigned char* _src = (unsigned char*)pSrc;
	unsigned char* _dst = (unsigned char*)pDst;
	size_t   len;
	for (len = size / wordsize; len--; _src += wordsize, _dst += wordsize)
		*(size_t*)_dst = *(size_t*)_src;

	len = size % wordsize;
	while (len--)
		*_dst++ = *_src++;
}