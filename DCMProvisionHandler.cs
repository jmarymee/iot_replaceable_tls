
using System.Collections.Generic;
using System.Linq;

using System.Diagnostics.Contracts;
using System.IO;
using System.Runtime.InteropServices;
using System.IO.Compression;
using System.Threading.Tasks;
using DotNetty.Buffers;
using DotNetty.Codecs.Mqtt.Packets;
using DotNetty.Common.Utilities;
using DotNetty.Transport.Channels;
using System;

using System.Text;

namespace ProtocolGateway.Host.Common
{
    class DCMProvisionHandler: ChannelHandlerAdapter
    {
        short step = 0;
        int secretSize = 1024;
        static bool isEncrypt = true; 

        public override void ChannelActive(IChannelHandlerContext context)
        {
            // this statement should be enable or disabled based on the result of the key exchange to
            // enable the traffic to reach to the upper layers or not
            context.FireChannelActive();
           // message.Release();

        }


        //===============================
        public override void ChannelRead(IChannelHandlerContext context, object message)
        {
            var buffer = message as IByteBuffer;

            switch (step)
               {
                   case 0:
                    Console.WriteLine("Case 0"); // Diffie hellman send 
                    Console.WriteLine("Received (Echo): " + buffer.ToString(Encoding.UTF8));
                    if ((buffer.ToString(Encoding.UTF8)).Equals("ENCRYPT\0"))
                    {
                        Console.WriteLine("Encryption has been requested");
                        isEncrypt = true;
                    }
                    else
                    {
                        Console.WriteLine("No encryption has been requested");
                        isEncrypt = false;
                    }
                    //===============send reply
                    IByteBuffer tempmessage = Unpooled.Buffer(secretSize);
                    byte[] msgbytes = new byte[secretSize];
                    byte x = 0;

                    for (int i = 0; i < secretSize; i++)
                        msgbytes[i] = (x++);

                    tempmessage.WriteBytes(msgbytes); //Alice send the public key to Bob

                    Console.WriteLine("ChannelActive Sending dummy initilalization sequence");

                    context.WriteAndFlushAsync(tempmessage);
                    //=================end send

                    step = 1;

                       break;

                   case 1:
                    if (buffer != null)
                    {
                        Console.WriteLine("Received (Enc): " + buffer.ToString(Encoding.UTF8));
                    }

                    //Do nothing to the message if not encrypted
                    if (isEncrypt)
                    {
                        for (int i = 0; i < buffer.ToArray().GetLength(0); i++)
                        {
                            byte temp;
                            temp = (byte)(buffer.GetByte(i) ^ 0x1);
                            buffer.SetByte(i, temp);

                        }
                    }
                    Console.WriteLine("Received (Clear) " + buffer.ToString(Encoding.UTF8));

                    step = 1;

                    //    Console.WriteLine("Case 1"); // Normal MQTT traffic
                    context.FireChannelRead(message);
                       break;

                   default:
                       Console.WriteLine("Default case");
                       break;
               }
        }

       public override Task WriteAsync(IChannelHandlerContext context, object message)
       {
            var buffer = message as IByteBuffer;
            if (buffer != null)
            {
                Console.WriteLine("Sending :(Clear) " + buffer.ToString(Encoding.UTF8));
            }

            if (isEncrypt)
            {
                for (int i = 0; i < buffer.ToArray().GetLength(0); i++)
                {
                    byte temp;
                    temp = (byte)(buffer.GetByte(i) ^ 0x1);
                    buffer.SetByte(i, temp);

                }
            }
            Console.WriteLine("sending :(ENC) " + buffer.ToString(Encoding.UTF8));

            return context.WriteAsync(message);
       }
    }
}