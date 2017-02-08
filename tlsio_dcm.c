// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

//TODO: This define can be used to test the protocol using a wire sniffer. If set then the handshake code will send a 'DCM_ENCRYPT' to the DCMProvisionHandler. 
// If the Gateway code sees that it sets a static boolean that executes a two's complement 'encryption' for sends and receives. The only exception is the server->client part of
// the handshake. During handshake, the client sends either DCM_ENCRYPT or NO_ENCRYPT and the server responds with a 'key' that is 1024 bytes long and is used for NOTHING. 
// It's only there to show how one might implement a handshake to establish a mutual encryption key. SSL uses DIffie-Helman, DCM uses a table seed. Handshake is ALWAYS unencrypted in this code
// Simply comment out the #define DCM_ENCRYPT to tell the clients (which tells the server) that you do not want 'encryption'. 
#define DCM_ENCRYPT

#define SECURITY_WIN32
#ifdef WINCE
#define UNICODE // Only Unicode version of secur32.lib functions supported on Windows CE
#define SCH_USE_STRONG_CRYPTO  0x00400000 // not defined in header file
#endif

#ifdef UNICODE
#define SEC_TCHAR   SEC_WCHAR
#else
#define SEC_TCHAR   SEC_CHAR
#endif

#include <stdlib.h>
#ifdef _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif


#include <stddef.h>
#include <stdio.h>
#include <stdbool.h>
//TODO: The include below (tlsio.h) is the original one used for tlsio_schannel. It's so minimal there is no reason to dupe, but feel free if you want!
#include "azure_c_shared_utility/tlsio.h"
//TODO: This is the header for this new c file (tlsio_dcm.c). It adds two new methods in the code that execute encrypt and decrypt functions. This should be replaced by real crypto
// Even though 2's complement works both ways (you could have ONE function for this) I made it as two since they can be two separate functions for real crypto
#include "azure_c_shared_utility/tlsio_dcm.h"
#include "azure_c_shared_utility/socketio.h"
#include "windows.h"
#include "sspi.h"
#include "schannel.h"
#include "azure_c_shared_utility/xlogging.h"
#include "azure_c_shared_utility/x509_schannel.h"
#include "azure_c_shared_utility/crt_abstractions.h"

typedef enum TLSIO_STATE_TAG
{
	TLSIO_STATE_NOT_OPEN,
	TLSIO_STATE_OPENING_UNDERLYING_IO,
	TLSIO_STATE_HANDSHAKE_CLIENT_HELLO_SENT,
	TLSIO_STATE_HANDSHAKE_SERVER_HELLO_RECEIVED,
	TLSIO_STATE_OPEN,
	TLSIO_STATE_CLOSING,
	TLSIO_STATE_ERROR
} TLSIO_STATE;

//Used for faux DCM Init
typedef struct DCM_INFO
{
	TLSIO_STATE tlsio_dcm_state;
	const char* initData;
} DCM_INSTANCE;

typedef struct TLS_IO_INSTANCE_TAG
{
	XIO_HANDLE socket_io;
	ON_IO_OPEN_COMPLETE on_io_open_complete;
	ON_IO_CLOSE_COMPLETE on_io_close_complete;
	ON_BYTES_RECEIVED on_bytes_received;
	ON_IO_ERROR on_io_error;
	void* on_io_open_complete_context;
	void* on_io_close_complete_context;
	void* on_bytes_received_context;
	void* on_io_error_context;
	CtxtHandle security_context;
	TLSIO_STATE tlsio_state;
	SEC_TCHAR* host_name;
	CredHandle credential_handle;
	bool credential_handle_allocated;
	unsigned char* received_bytes;
	size_t received_byte_count;
	size_t buffer_size;
	size_t needed_bytes;
	const char* x509certificate;
	const char* x509privatekey;
	X509_SCHANNEL_HANDLE x509_schannel_handle;
} TLS_IO_INSTANCE;


/*this function will clone an option given by name and value*/
static void* tlsio_dcm_CloneOption(const char* name, const void* value)
{
	void* result;
	if (
		(name == NULL) || (value == NULL)
		)
	{
		LogError("invalid parameter detected: const char* name=%p, const void* value=%p", name, value);
		result = NULL;
	}
	else
	{
		if (strcmp(name, "x509certificate") == 0)
		{
			if (mallocAndStrcpy_s((char**)&result, (const char *)value) != 0)
			{
				LogError("unable to mallocAndStrcpy_s x509certificate value");
				result = NULL;
			}
			else
			{
				/*return as is*/
			}
		}
		else if (strcmp(name, "x509privatekey") == 0)
		{
			if (mallocAndStrcpy_s((char**)&result, (const char *)value) != 0)
			{
				LogError("unable to mallocAndStrcpy_s x509privatekey value");
				result = NULL;
			}
			else
			{
				/*return as is*/
			}
		}
		else
		{
			LogError("not handled option : %s", name);
			result = NULL;
		}
	}
	return result;
}

/*this function destroys an option previously created*/
static void tlsio_dcm_DestroyOption(const char* name, const void* value)
{
	/*since all options for this layer are actually string copies., disposing of one is just calling free*/
	if (
		(name == NULL) || (value == NULL)
		)
	{
		LogError("invalid parameter detected: const char* name=%p, const void* value=%p", name, value);
	}
	else
	{
		if (
			(strcmp(name, "x509certificate") == 0) ||
			(strcmp(name, "x509privatekey") == 0)
			)
		{
			free((void*)value);
		}
		else
		{
			LogError("not handled option : %s", name);
		}
	}
}

static OPTIONHANDLER_HANDLE tlsio_dcm_retrieveoptions(CONCRETE_IO_HANDLE handle)
{
	OPTIONHANDLER_HANDLE result;
	if (handle == NULL)
	{
		LogError("invalid parameter detected: CONCRETE_IO_HANDLE handle=%p", handle);
		result = NULL;
	}
	else
	{
		result = OptionHandler_Create(tlsio_dcm_CloneOption, tlsio_dcm_DestroyOption, tlsio_dcm_setoption);
		if (result == NULL)
		{
			LogError("unable to OptionHandler_Create");
			/*return as is*/
		}
		else
		{
			/*this layer cares about the certificates and the x509 credentials*/
			TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)handle;
			if (
				(tls_io_instance->x509certificate != NULL) &&
				(OptionHandler_AddOption(result, "x509certificate", tls_io_instance->x509certificate) != 0)
				)
			{
				LogError("unable to save x509certificate option");
				OptionHandler_Destroy(result);
				result = NULL;
			}
			else if (
				(tls_io_instance->x509privatekey != NULL) &&
				(OptionHandler_AddOption(result, "x509privatekey", tls_io_instance->x509privatekey) != 0)
				)
			{
				LogError("unable to save x509privatekey option");
				OptionHandler_Destroy(result);
				result = NULL;
			}
			else
			{
				/*all is fine, all interesting options have been saved*/
				/*return as is*/
			}
		}
	}
	return result;
}

static const IO_INTERFACE_DESCRIPTION tlsio_dcm_interface_description =
{
	tlsio_dcm_retrieveoptions,
	tlsio_dcm_create,
	tlsio_dcm_destroy,
	tlsio_dcm_open,
	tlsio_dcm_close,
	tlsio_dcm_send,
	tlsio_dcm_dowork,
	tlsio_dcm_setoption
};

static void indicate_error(TLS_IO_INSTANCE* tls_io_instance)
{
	if (tls_io_instance->on_io_error != NULL)
	{
		tls_io_instance->on_io_error(tls_io_instance->on_io_error_context);
	}
}

static int resize_receive_buffer(TLS_IO_INSTANCE* tls_io_instance, size_t needed_buffer_size)
{
	int result;

	if (needed_buffer_size > tls_io_instance->buffer_size)
	{
		unsigned char* new_buffer = (unsigned char*)realloc(tls_io_instance->received_bytes, needed_buffer_size);
		if (new_buffer == NULL)
		{
			result = __LINE__;
		}
		else
		{
			tls_io_instance->received_bytes = new_buffer;
			tls_io_instance->buffer_size = needed_buffer_size;
			result = 0;
		}
	}
	else
	{
		result = 0;
	}

	return result;
}

static void on_underlying_io_close_complete(void* context)
{
	TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)context;
	if (tls_io_instance->tlsio_state == TLSIO_STATE_CLOSING)
	{
		tls_io_instance->tlsio_state = TLSIO_STATE_NOT_OPEN;
		if (tls_io_instance->on_io_close_complete != NULL)
		{
			tls_io_instance->on_io_close_complete(tls_io_instance->on_io_close_complete_context);
		}

		/* Free security context resources corresponding to creation with open */
		//DeleteSecurityContext(&tls_io_instance->security_context); //TODO: Removed since we don't have a security context (This was for SSL Version)

		if (tls_io_instance->credential_handle_allocated)
		{
			(void)FreeCredentialHandle(&tls_io_instance->credential_handle);
			tls_io_instance->credential_handle_allocated = false;
		}
	}
}



//TODO: Security init should start here. In TLS/SSL this is where the client sends the TLS Hello and then the server respondsd with a server Cert plus auth type list
// In our exmaple case we decided if crypto is desired or not during handshake. The handshake starts here and ends with 'on_underlying_io_bytes_received'
// When this method is called, it merely means he SYN/SYN/ACK for TCP/IP has been established. 
static void on_underlying_io_open_complete(void* context, IO_OPEN_RESULT io_open_result)
{
	TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)context;
	DCM_INSTANCE dcm_info;
#ifdef DCM_ENCRYPT
	dcm_info.initData = "ENCRYPT"; //Client->Server initial handshake. In SSL this would be a client HELLO
#else
	dcm_info.initData = "NO_ENCRYPT"; //Client->Server initial handshake. In SSL this would be a client HELLO
#endif


	if (tls_io_instance->tlsio_state != TLSIO_STATE_OPENING_UNDERLYING_IO)
	{
		tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
		indicate_error(tls_io_instance);
	}
	else
	{
		if (io_open_result != IO_OPEN_OK)
		{
			tls_io_instance->tlsio_state = TLSIO_STATE_NOT_OPEN;
			if (tls_io_instance->on_io_open_complete != NULL)
			{
				tls_io_instance->on_io_open_complete(tls_io_instance->on_io_open_complete_context, IO_OPEN_ERROR);
			}
		}
		else
		{
			// This is where the handshake data is sent via an abstracted socket IO function pointer. Doing ti this way
			// Means that we can run this cross-platform (not just winsock)
			if (xio_send(tls_io_instance->socket_io, dcm_info.initData, (strlen(dcm_info.initData) + 1), NULL, NULL) != 0)
			{
				tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
				indicate_error(tls_io_instance);
			}
			else
			{
				//This is a funky way that this code deals with non-blocking socket IO. The 'needed_bytes' value is a sort of flag that makes 'on_underlying_io_bytes_received'
				// look for incoming data from the receive socket. Best drawn on a white board or you can step through code if you so dare! 
				tls_io_instance->needed_bytes = 1;
				if (resize_receive_buffer(tls_io_instance, tls_io_instance->needed_bytes + tls_io_instance->received_byte_count) != 0)
				{
					tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
					indicate_error(tls_io_instance);
				}
				else
				{
					tls_io_instance->tlsio_state = TLSIO_STATE_HANDSHAKE_CLIENT_HELLO_SENT;
				}
			}
		}
	}
}

static int set_receive_buffer(TLS_IO_INSTANCE* tls_io_instance, size_t buffer_size)
{
	int result;

	unsigned char* new_buffer = (unsigned char*)realloc(tls_io_instance->received_bytes, buffer_size);
	if (new_buffer == NULL)
	{
		result = __LINE__;
	}
	else
	{
		tls_io_instance->received_bytes = new_buffer;
		tls_io_instance->buffer_size = buffer_size;
		result = 0;
	}

	return result;
}

static void on_underlying_io_bytes_received(void* context, const unsigned char* buffer, size_t size)
{
	TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)context;
	size_t consumed_bytes;
	unsigned char * cbuffer;

	if (resize_receive_buffer(tls_io_instance, tls_io_instance->received_byte_count + size) == 0)
	{
		memcpy(tls_io_instance->received_bytes + tls_io_instance->received_byte_count, buffer, size);
		tls_io_instance->received_byte_count += size;

		if (size > tls_io_instance->needed_bytes)
		{
			tls_io_instance->needed_bytes = 0;
		}
		else
		{
			tls_io_instance->needed_bytes -= size;
		}
		//TODO: The above code will iterate and add received bytes (and the total count) from the underlying socket IO. We assume that we get everything in one receive
		// But if there are split frames larger than a max TCPIP packet you *may* have to track that you have bytes but not enough. Ethernet is 1500 so if ethernet then that's the limit
		while (tls_io_instance->needed_bytes == 0)
		{
			if (tls_io_instance->tlsio_state == TLSIO_STATE_HANDSHAKE_CLIENT_HELLO_SENT)
			{
				if (tls_io_instance->received_byte_count == 1024)
				{
					consumed_bytes = tls_io_instance->received_byte_count;
					tls_io_instance->received_byte_count -= consumed_bytes;
					/* if nothing more to consume, set the needed bytes to 1, to get on the next byte how many we actually need */
					tls_io_instance->needed_bytes = tls_io_instance->received_byte_count == 0 ? 1 : 0;


					//Resize the receive buffer for the next set of inbound network data unrelated to this handshake
					// We are resetting back to 1 byte. I think that means we won't memory leak here
					if (set_receive_buffer(tls_io_instance, tls_io_instance->needed_bytes + tls_io_instance->received_byte_count) != 0)
					{
						tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
						if (tls_io_instance->on_io_open_complete != NULL)
						{
							tls_io_instance->on_io_open_complete(tls_io_instance->on_io_open_complete_context, IO_OPEN_ERROR);
						}
					}
					else
					{
						//Handshake done; now time for MQTT connect and ACK IF we we are using MQTT. This layer shouldn't care....
						tls_io_instance->tlsio_state = TLSIO_STATE_OPEN;
						if (tls_io_instance->on_io_open_complete != NULL)
						{
							tls_io_instance->on_io_open_complete(tls_io_instance->on_io_open_complete_context, IO_OPEN_OK);
						}
					}
				}
				else
				{
					tls_io_instance->needed_bytes = 1024 - tls_io_instance->received_byte_count;
				}
			}
			else if (tls_io_instance->tlsio_state == TLSIO_STATE_OPEN)
			{
				consumed_bytes = tls_io_instance->received_byte_count;
				if (tls_io_instance->on_bytes_received != NULL)
				{
					int ccode = -1; //Long form to see if we got an error when decoding
					//Note that we modify the one and only copy of the data. If we corrupt then we are in trouble.
					// Perhaps a better way would be a calloc / memcopy / decrypt / discard (for security reasons). Future enhancement
					cbuffer = tls_io_instance->received_bytes;  
					size_t len = tls_io_instance->received_byte_count;
					ccode = DecodeBuffer(cbuffer, len);
					//ccode = 0;
					if (ccode == 0)
					{
						//This is part of the flexible yet convoluted abstracted interfaces. We call this fnPtr (on_bytes_received) which maps to the MQTT client
						// Were this AMQP it would map there instead. HTTP/REST - same. In this case it tells the higher layer that we can now communicate 'securely' 
						// and it can now begin it's client-connect procedures
						tls_io_instance->on_bytes_received(tls_io_instance->on_bytes_received_context, cbuffer, tls_io_instance->received_byte_count);
					}
				}

				tls_io_instance->received_byte_count -= consumed_bytes;

				/* if nothing more to consume, set the needed bytes to 1, to get on the next byte how many we actually need */
				tls_io_instance->needed_bytes = tls_io_instance->received_byte_count == 0 ? 1 : 0;

				if (set_receive_buffer(tls_io_instance, tls_io_instance->needed_bytes + tls_io_instance->received_byte_count) != 0)
				{
					tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
					indicate_error(tls_io_instance);
				}
			}
		}
	}
}

static void on_underlying_io_error(void* context)
{
	TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)context;

	switch (tls_io_instance->tlsio_state)
	{
	default:
	case TLSIO_STATE_NOT_OPEN:
	case TLSIO_STATE_ERROR:
		break;

	case TLSIO_STATE_OPENING_UNDERLYING_IO:
	case TLSIO_STATE_HANDSHAKE_CLIENT_HELLO_SENT:
	case TLSIO_STATE_HANDSHAKE_SERVER_HELLO_RECEIVED:
		tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
		if (tls_io_instance->on_io_open_complete != NULL)
		{
			tls_io_instance->on_io_open_complete(tls_io_instance->on_io_open_complete_context, IO_OPEN_ERROR);
		}
		break;

	case TLSIO_STATE_CLOSING:
		tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
		if (tls_io_instance->on_io_close_complete != NULL)
		{
			tls_io_instance->on_io_close_complete(tls_io_instance->on_io_close_complete_context);
		}
		break;

	case TLSIO_STATE_OPEN:
		tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
		indicate_error(tls_io_instance);
		break;
	}
}

CONCRETE_IO_HANDLE tlsio_dcm_create(void* io_create_parameters)
{
	TLSIO_CONFIG* tls_io_config = (TLSIO_CONFIG *)io_create_parameters;
	TLS_IO_INSTANCE* result;

	if (tls_io_config == NULL)
	{
		result = NULL;
	}
	else
	{
		result = (TLS_IO_INSTANCE *)malloc(sizeof(TLS_IO_INSTANCE));
		if (result != NULL)
		{
			SOCKETIO_CONFIG socketio_config;

			socketio_config.hostname = tls_io_config->hostname;
			socketio_config.port = tls_io_config->port;
			socketio_config.accepted_socket = NULL;

			result->on_bytes_received = NULL;
			result->on_io_open_complete = NULL;
			result->on_io_close_complete = NULL;
			result->on_io_error = NULL;
			result->on_io_open_complete_context = NULL;
			result->on_io_close_complete_context = NULL;
			result->on_bytes_received_context = NULL;
			result->on_io_error_context = NULL;
			result->credential_handle_allocated = false;
			result->x509_schannel_handle = NULL;

			result->host_name = (SEC_TCHAR*)malloc(sizeof(SEC_TCHAR) * (1 + strlen(tls_io_config->hostname)));

			if (result->host_name == NULL)
			{
				free(result);
				result = NULL;
			}
			else
			{
#ifdef WINCE
				(void) mbstowcs(result->host_name, tls_io_config->hostname, strlen(tls_io_config->hostname));
#else
				(void)strcpy(result->host_name, tls_io_config->hostname);
#endif

				const IO_INTERFACE_DESCRIPTION* socket_io_interface = socketio_get_interface_description();
				if (socket_io_interface == NULL)
				{
					free(result->host_name);
					free(result);
					result = NULL;
				}
				else
				{
					result->socket_io = xio_create(socket_io_interface, &socketio_config);
					if (result->socket_io == NULL)
					{
						free(result->host_name);
						free(result);
						result = NULL;
					}
					else
					{
						result->received_bytes = NULL;
						result->received_byte_count = 0;
						result->buffer_size = 0;
						result->tlsio_state = TLSIO_STATE_NOT_OPEN;
						result->x509certificate = NULL;
						result->x509privatekey = NULL;
						result->x509_schannel_handle = NULL;
					}
				}
			}
		}
	}

	return result;
}

void tlsio_dcm_destroy(CONCRETE_IO_HANDLE tls_io)
{
	if (tls_io != NULL)
	{
		TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;
		if (tls_io_instance->credential_handle_allocated)
		{
			(void)FreeCredentialHandle(&tls_io_instance->credential_handle);
			tls_io_instance->credential_handle_allocated = false;
		}

		if (tls_io_instance->received_bytes != NULL)
		{
			free(tls_io_instance->received_bytes);
		}

		if (tls_io_instance->x509_schannel_handle != NULL)
		{
			x509_schannel_destroy(tls_io_instance->x509_schannel_handle);
		}

		xio_destroy(tls_io_instance->socket_io);
		free(tls_io_instance->host_name);
		free(tls_io);
	}
}

int tlsio_dcm_open(CONCRETE_IO_HANDLE tls_io, ON_IO_OPEN_COMPLETE on_io_open_complete, void* on_io_open_complete_context, ON_BYTES_RECEIVED on_bytes_received, void* on_bytes_received_context, ON_IO_ERROR on_io_error, void* on_io_error_context)
{
	int result;

	if (tls_io == NULL)
	{
		result = __LINE__;
	}
	else
	{
		TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;

		if (tls_io_instance->tlsio_state != TLSIO_STATE_NOT_OPEN)
		{
			result = __LINE__;
		}
		else
		{
			tls_io_instance->on_io_open_complete = on_io_open_complete;
			tls_io_instance->on_io_open_complete_context = on_io_open_complete_context;

			tls_io_instance->on_bytes_received = on_bytes_received;
			tls_io_instance->on_bytes_received_context = on_bytes_received_context;

			tls_io_instance->on_io_error = on_io_error;
			tls_io_instance->on_io_error_context = on_io_error_context;

			tls_io_instance->tlsio_state = TLSIO_STATE_OPENING_UNDERLYING_IO;

			if (xio_open(tls_io_instance->socket_io, on_underlying_io_open_complete, tls_io_instance, on_underlying_io_bytes_received, tls_io_instance, on_underlying_io_error, tls_io_instance) != 0)
			{
				result = __LINE__;
				tls_io_instance->tlsio_state = TLSIO_STATE_NOT_OPEN;
			}
			else
			{
				result = 0;
			}
		}
	}

	return result;
}

int tlsio_dcm_close(CONCRETE_IO_HANDLE tls_io, ON_IO_CLOSE_COMPLETE on_io_close_complete, void* callback_context)
{
	int result = 0;

	if (tls_io == NULL)
	{
		result = __LINE__;
	}
	else
	{
		TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;

		if ((tls_io_instance->tlsio_state == TLSIO_STATE_NOT_OPEN) ||
			(tls_io_instance->tlsio_state == TLSIO_STATE_CLOSING))
		{
			result = __LINE__;
		}
		else
		{
			tls_io_instance->tlsio_state = TLSIO_STATE_CLOSING;
			tls_io_instance->on_io_close_complete = on_io_close_complete;
			tls_io_instance->on_io_close_complete_context = callback_context;
			if (xio_close(tls_io_instance->socket_io, on_underlying_io_close_complete, tls_io_instance) != 0)
			{
				result = __LINE__;
			}
			else
			{
				result = 0;
			}
		}
	}

	return result;
}

// TODO: This is where one would implement the crypto for the outbound send. Note that this simple example 'encrypts' the buffer (if encryption is on) and then sends via
// the abstracted Socket IO interface
static int send_chunk(CONCRETE_IO_HANDLE tls_io, const void* buffer, size_t size, ON_SEND_COMPLETE on_send_complete, void* callback_context)
{
	int result = -1; //Default to error
	unsigned char* encryptBuffer = NULL; //This is a recast ptr to the data buffer pre-encryption. Convenience mostly
	int ccode = -1; //default to error

	if ((tls_io == NULL) ||
		(buffer == NULL) ||
		(size == 0))
	{
		/* Invalid arguments */
		result = __LINE__;
	}
	else
	{
		TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;
		if (tls_io_instance->tlsio_state != TLSIO_STATE_OPEN)
		{
			result = __LINE__;
		}
		else
		{
			//TODO: Here is the simple 2's complement encryption
			encryptBuffer = (unsigned char *)buffer;
			ccode = EncodeBuffer(encryptBuffer, size);
			//ccode = 0;
			if (ccode == 0)
			{
				if (xio_send(tls_io_instance->socket_io, buffer, size, on_send_complete, callback_context) != 0)
				{
					result = __LINE__;
				}
				else
				{
					result = 0;
				}
			}
		}
	}

	return result;
}

int tlsio_dcm_send(CONCRETE_IO_HANDLE tls_io, const void* buffer, size_t size, ON_SEND_COMPLETE on_send_complete, void* callback_context)
{
	int result;

	while (size > 0)
	{
		size_t to_send = 16 * 1024;
		if (to_send > size)
		{
			to_send = size;
		}

		if (send_chunk(tls_io, buffer, to_send, (to_send == size) ? on_send_complete : NULL, callback_context) != 0)
		{
			break;
		}

		size -= to_send;
		buffer = ((const unsigned char*)buffer) + to_send;
	}

	if (size > 0)
	{
		result = __LINE__;
	}
	else
	{
		result = 0;
	}

	return result;
}

void tlsio_dcm_dowork(CONCRETE_IO_HANDLE tls_io)
{
	if (tls_io != NULL)
	{
		TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;
		xio_dowork(tls_io_instance->socket_io);
	}
}

int tlsio_dcm_setoption(CONCRETE_IO_HANDLE tls_io, const char* optionName, const void* value)
{
	int result;

	if (tls_io == NULL || optionName == NULL)
	{
		result = __LINE__;
	}
	else
	{
		TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;
		/*x509certificate and x509privatekey are "referenced" by this layer*/
		if (strcmp("x509certificate", optionName) == 0)
		{
			if (tls_io_instance->x509certificate != NULL)
			{
				LogError("unable to set x509 options more than once");
				result = __LINE__;
			}
			else
			{
				tls_io_instance->x509certificate = (const char *)tlsio_dcm_CloneOption("x509certificate", value);
				if (tls_io_instance->x509privatekey != NULL)
				{
					tls_io_instance->x509_schannel_handle = x509_schannel_create(tls_io_instance->x509certificate, tls_io_instance->x509privatekey);
					if (tls_io_instance->x509_schannel_handle == NULL)
					{
						LogError("x509_schannel_create failed");
						result = __LINE__;
					}
					else
					{
						/*all is fine, the x509 shall be used later*/
						result = 0;
					}
				}
				else
				{
					result = 0; /*all is fine, maybe x509 privatekey will come and then x509 is set*/
				}
			}
		}
		else if (strcmp("x509privatekey", optionName) == 0)
		{
			if (tls_io_instance->x509privatekey != NULL)
			{
				LogError("unable to set more than once x509 options");
				result = __LINE__;
			}
			else
			{
				tls_io_instance->x509privatekey = (const char *)tlsio_dcm_CloneOption("x509privatekey", value);
				if (tls_io_instance->x509certificate != NULL)
				{
					tls_io_instance->x509_schannel_handle = x509_schannel_create(tls_io_instance->x509certificate, tls_io_instance->x509privatekey);
					if (tls_io_instance->x509_schannel_handle == NULL)
					{
						LogError("x509_schannel_create failed");
						result = __LINE__;
					}
					else
					{
						/*all is fine, the x509 shall be used later*/
						result = 0;
					}
				}
				else
				{
					result = 0; /*all is fine, maybe x509 privatekey will come and then x509 is set*/
				}
			}
		}
		else if (tls_io_instance->socket_io == NULL)
		{
			result = __LINE__;
		}
		else
		{
			result = xio_setoption(tls_io_instance->socket_io, optionName, value);
		}
	}

	return result;
}

// TODO: Used as a sample to decrypt a 2's complement demo encryption. Note that Encode and Decode are identical for 2C :)
int DecodeBuffer(unsigned char* buffer, size_t len)
{
	if (len > 0) {}
	if (buffer != NULL) {}
#ifdef DCM_ENCRYPT
	unsigned char *pBuf = (unsigned char *)buffer;
	for (size_t i = 0;i<len;i++) { //Here is where we will do the decoding
		*(pBuf + i) ^= 1;
	}
#endif
	return 0;
}

// TODO: Used as a sample to decrypt a 2's complement demo encryption. Note that Encode and Decode are identical for 2C :)
int EncodeBuffer(unsigned char* buffer, size_t len)
{
	if (len > 0) {}
	if (buffer != NULL) {}
#ifdef DCM_ENCRYPT
	unsigned char *pBuf = (unsigned char *)buffer;
	for (size_t i = 0; i<len; i++) { //Here is where we will do the encoding
		*(pBuf + i) ^= 1;
	}
#endif
	return 0;
}

const IO_INTERFACE_DESCRIPTION* tlsio_dcm_get_interface_description(void)
{
	return &tlsio_dcm_interface_description;
}
