// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>
#ifdef _CRT_DBG_MAP_ALLOC
#include <crtdbg.h>
#endif // _CRT_DBG_MAP_ALLOC
#include <stdarg.h>
#include <stdio.h>
#include <conio.h>
#include "mqtt_client_sample.h"
#include "azure_umqtt_c/mqtt_client.h"
//#include "azure_c_shared_utility/socketio.h"
#include "azure_c_shared_utility/platform.h"
//#include "azure_c_shared_utility/tlsio_apqssl.h"
#include "azure_c_shared_utility/tlsio_dcm.h"
#include "azure_c_shared_utility/tlsio.h"

static const char* TOPIC_SUB_NAME_A = "devices/APQDevice/messages/devicebound/#";
//static const char* TOPIC_SUB_NAME_B = "/devices/APQDevice/messages/devicebound";
static const char* TOPIC_NAME_A = "/devices/APQDevice/messages/events";
static const char* TOPIC_NAME_B = "/devices/APQDevice/messages/events";
static const char* APP_NAME_A = "This is the app msg A.";
static const char* APP_NAME_B = "This is the app msg B.";
//static const char* HOSTNAME = "protocol-gateway.contoso.com";
static unsigned int sent_messages = 0;

static uint16_t PACKET_ID_VALUE = 11;
static bool g_continue = true;

#define PORT_NUM_UNENCRYPTED        1883
#define PORT_NUM_ENCRYPTED          8883
#define PORT_NUM_ENCRYPTED_CERT     8884

#define DEFAULT_MSG_TO_SEND         1

static const char* QosToString(QOS_VALUE qosValue)
{
    switch (qosValue)
    {
        case DELIVER_AT_LEAST_ONCE: return "Deliver_At_Least_Once";
        case DELIVER_EXACTLY_ONCE: return "Deliver_Exactly_Once";
        case DELIVER_AT_MOST_ONCE: return "Deliver_At_Most_Once";
        case DELIVER_FAILURE: return "Deliver_Failure";
    }
    return "";
}

static void OnRecvCallback(MQTT_MESSAGE_HANDLE msgHandle, void* context)
{
    (void)context;
    const APP_PAYLOAD* appMsg = mqttmessage_getApplicationMsg(msgHandle);

    (void)printf("Incoming Msg: Packet Id: %d\r\nQOS: %s\r\nTopic Name: %s\r\nIs Retained: %s\r\nIs Duplicate: %s\r\nApp Msg: ", mqttmessage_getPacketId(msgHandle),
        QosToString(mqttmessage_getQosType(msgHandle) ),
        mqttmessage_getTopicName(msgHandle),
        mqttmessage_getIsRetained(msgHandle) ? "true" : "false",
        mqttmessage_getIsDuplicateMsg(msgHandle) ? "true" : "false"
        );
    for (size_t index = 0; index < appMsg->length; index++)
    {
        (void)printf("0x%x", appMsg->message[index]);
    }

    (void)printf("\r\n");
}

static void OnCloseComplete(void* context)
{
    (void)context;

    (void)printf("%d: On Close Connection failed\r\n", __LINE__);
}

static void SendCannedMessageTest(MQTT_CLIENT_HANDLE handle)
{
	MQTT_MESSAGE_HANDLE msg = mqttmessage_create(PACKET_ID_VALUE++, TOPIC_NAME_A, DELIVER_AT_MOST_ONCE, (const uint8_t*)APP_NAME_A, strlen(APP_NAME_A));
	if (msg == NULL)
	{
		(void)printf("%d: mqttmessage_create failed\r\n", __LINE__);
		g_continue = false;
	}
	else
	{
		if (mqtt_client_publish(handle, msg))
		{
			(void)printf("%d: mqtt_client_publish failed\r\n", __LINE__);
			g_continue = false;
		}
		else
		{
			(void)printf("Message A and B sent\r\n");
		}
		mqttmessage_destroy(msg);
	}
}

static void OnOperationComplete(MQTT_CLIENT_HANDLE handle, MQTT_CLIENT_EVENT_RESULT actionResult, const void* msgInfo, void* callbackCtx)
{
    (void)msgInfo;
    (void)callbackCtx;
    switch (actionResult)
    {
        case MQTT_CLIENT_ON_CONNACK:
        {
            (void)printf("ConnAck function called\r\n");

            SUBSCRIBE_PAYLOAD subscribe[1];
            subscribe[0].subscribeTopic = TOPIC_SUB_NAME_A;
            subscribe[0].qosReturn = DELIVER_AT_LEAST_ONCE;
            //subscribe[1].subscribeTopic = TOPIC_SUB_NAME_B;
            //subscribe[1].qosReturn = DELIVER_AT_MOST_ONCE;

            //if (mqtt_client_subscribe(handle, PACKET_ID_VALUE++, subscribe, sizeof(subscribe) / sizeof(subscribe[0])) != 0)
			//unsigned int count = sizeof(subscribe) / sizeof(subscribe[0]);
			if (mqtt_client_subscribe(handle, PACKET_ID_VALUE++, subscribe, sizeof(subscribe) / sizeof(subscribe[0])) != 0)
            {
                (void)printf("%d: mqtt_client_subscribe failed\r\n", __LINE__);
                g_continue = false;
            }
            break;
        }
        case MQTT_CLIENT_ON_SUBSCRIBE_ACK:
        {
            MQTT_MESSAGE_HANDLE msg = mqttmessage_create(PACKET_ID_VALUE++, TOPIC_NAME_A, DELIVER_AT_MOST_ONCE, (const uint8_t*)APP_NAME_A, strlen(APP_NAME_A));
			MQTT_MESSAGE_HANDLE msg_b = mqttmessage_create(PACKET_ID_VALUE++, TOPIC_NAME_B, DELIVER_AT_MOST_ONCE, (const uint8_t*)APP_NAME_B, strlen(APP_NAME_B));
            if (msg == NULL || msg_b == NULL)
            {
                (void)printf("%d: mqttmessage_create failed\r\n", __LINE__);
                g_continue = false;
            }
            else
            {
                if (mqtt_client_publish(handle, msg) || mqtt_client_publish(handle, msg_b))
                {
                    (void)printf("%d: mqtt_client_publish failed\r\n", __LINE__);
                    g_continue = false;
                }
				else
				{
					(void)printf("Message A and B sent\r\n");
				}
                mqttmessage_destroy(msg);
				mqttmessage_destroy(msg_b);
            }
            // Now send a message that will get 
            break;
        }
        case MQTT_CLIENT_ON_PUBLISH_ACK:
        {
            break;
        }
        case MQTT_CLIENT_ON_PUBLISH_RECV:
        {
            break;
        }
        case MQTT_CLIENT_ON_PUBLISH_REL:
        {
            break;
        }
        case MQTT_CLIENT_ON_PUBLISH_COMP:
        {
            // Done so send disconnect
            mqtt_client_disconnect(handle);
            break;
        }
        case MQTT_CLIENT_ON_DISCONNECT:
            g_continue = false;
            break;
    }
}

static void OnErrorComplete(MQTT_CLIENT_HANDLE handle, MQTT_CLIENT_EVENT_ERROR error, void* callbackCtx)
{
    (void)callbackCtx;
    (void)handle;
    switch (error)
    {
    case MQTT_CLIENT_CONNECTION_ERROR:
    case MQTT_CLIENT_PARSE_ERROR:
    case MQTT_CLIENT_MEMORY_ERROR:
    case MQTT_CLIENT_COMMUNICATION_ERROR:
    case MQTT_CLIENT_NO_PING_RESPONSE:
    case MQTT_CLIENT_UNKNOWN_ERROR:
        g_continue = false;
        break;
    }
}

void mqtt_client_sample_run()
{
    if (platform_init() != 0)
    {
        (void)printf("platform_init failed\r\n");
    }
    else
    {
        MQTT_CLIENT_HANDLE mqttHandle = mqtt_client_init(OnRecvCallback, OnOperationComplete, NULL, OnErrorComplete, NULL);
        if (mqttHandle == NULL)
        {
            (void)printf("mqtt_client_init failed\r\n");
        }
        else
        {
            MQTT_CLIENT_OPTIONS options = { 0 };
            options.clientId = "APQDevice";
            options.willMessage = NULL;
            options.username = "APQIOTHub.azure-devices.net/APQDevice/api-version=2016-11-14";
            options.password = "SharedAccessSignature sr=APQIOTHub.azure-devices.net%2Fdevices%2FAPQDevice&sig=qAitci2rx1VnwdCl0naERNe3mFsCbFGlxHpmB6jwI3A%3D&se=1486928151";
            options.keepAliveInterval = 10;
            options.useCleanSession = true;
            options.qualityOfServiceValue = DELIVER_AT_LEAST_ONCE;

            //SOCKETIO_CONFIG config = {"protocol-gateway.contoso.com", PORT_NUM_ENCRYPTED, NULL};

			//const IO_INTERFACE_DESCRIPTION* tlsio_interface = platform_get_default_tlsio();
			//TLSIO_CONFIG config = { "APQIOTHub.azure-devices.net", PORT_NUM_ENCRYPTED };
			TLSIO_CONFIG config = { "protocol-gateway.contoso.com", PORT_NUM_ENCRYPTED };

            //XIO_HANDLE xio = xio_create(socketio_get_interface_description(), &config);
			//XIO_HANDLE xio = xio_create(tlsio_interface, &config);
			XIO_HANDLE xio = xio_create(tlsio_dcm_get_interface_description(), &config);
            if (xio == NULL)
            {
                (void)printf("xio_create failed\r\n");
            }
            else
            {
                if (mqtt_client_connect(mqttHandle, xio, &options) != 0)
                {
                    (void)printf("mqtt_client_connect failed\r\n");
                }
                else
                {
                    do
                    {
                        mqtt_client_dowork(mqttHandle);

						//Are we ready to quit and shutdown gracefully?
						if (_kbhit()) 
						{
							int key = _getch();
							if (key == 'q') {
								g_continue = false;
								mqtt_client_disconnect(mqttHandle);
							}
							if (key == 's') {
								SendCannedMessageTest(mqttHandle);
							}
						}
                    } while (g_continue);
                }
                xio_close(xio, OnCloseComplete, NULL);
            }
            mqtt_client_deinit(mqttHandle);
        }
        platform_deinit();
    }

#ifdef _CRT_DBG_MAP_ALLOC
    _CrtDumpMemoryLeaks();
#endif
}
