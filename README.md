# Azure IOT C SDK and Protocol Gateway Replaceable TLS
This project to show how to replace SSL under TLS with an alternative protocol. Why might you want to do this? In the general case, you may have a small-footprint IOT device that wants to send telemetry to the cloud with no intermediaries (device to cloud) but do so securely. Traditionally that meant a field gateway.

Using this example you can implement your own security protocols as a TLS implementation under the Azure C IOT SDK (specifically the `azuresharedutility` code) communicating with the Azure Protocol Gateway (using a Channel Handler). Buyer beware; creating your own security layer (like SSL) is an exercise best left to experts. Existing implementations have been around for years and have been vetted with peer reviews. This example code was developed to assist a ISV partner with implementing their security protocols (as security experts). 

## Creating a client TLS layer for specialized encryption hardware
A more general use of this example code is to demonstrate how an IOT device manufacturer could create a TLS layer that executes security instructions (like AES) on a hardware security module (HSM). The default library uses OpenSSL, SSL on Windows or WolfSSL to accomplished encrypted communications. While that is possible, it may tax the memory and computational limits of a small-footprint IOT device. If your device has an onboard HSM you can use this example code to see how to make HSM specific API calls for encryption versus the software only libraries.

This repo ONLY contains the modified source files for the Azure C IOT SDK and is for demonstration only. The Azure IOT keys *were* real ones (re-generated now but kept originals in code to see what they would look like.). 

## Replication the project (getting it running)
You will need several things to get the client communicating over the network to a locally running Azure Protocol Gateway. Some are optional (like Wireshark) but described and included in the flow for those and want to fully understand the interactions.

You will need to OBTAIN these things:
- A Fork of the Azure Shared Utility code with the DCM branch
- A Fork of the Azure Protocol Gateway with the DCM branch
- A Running Azure IOT Hub with at least one device created
- Azure IOT Device Explorer
- Current Azure SDK on machine where you will run the Azure Protocol Gateway (specifically you need the Azure Storage Emulator)
- (Optional but nice) Wireshark protocol analyzer with the NPCAP driver for capturing local loopback
- (Optional but nice) Azure Service Fabric SDK. The project will load cleaner with no errors. 

You will need to DO these things:
- Modify your local hosts file (C:\Windows\system32\drivers\etc\hosts) to point 127.0.0.1 to protocol-gateway.contoso.com
- Create an Azure IOT Hub with at least ONE device
- Obtain Azure IOT Hub Connection String and replace the one in the Azure Protocol Gateway 
- Obtain device info (name, a SAS key - generated from the Device Explorer, Azure IOT Hub URL)
- Update the uMQTT main.c code to add the device client info and other IOT Hub creds
- Run the Azure Storage Emulator locally (or where you will run the Azure Protocol Gateway DCM Branch)
- Execute the Device Explorer and add the Azure IOT Connection string. This will allow you to generate a device SAS and monitor telemetry sent to Azure IOT HUB as well as send cloud to device messages

## Goals to run the project
When you are ready to run, you will (in the simplest form) have the Azure Protocol Gateway (DCM branch) and the Azure IOT C SDK running on the same machine. Additionally you will have Wireshark ready to capture packets on the local loopback, looking for packets going to/coming from port 8883 (the default MQTT secure port but this can be anything as long as client and server agree in code).

The client will send an initial handshake. The server will respond with a pre-generated key (1024 bytes long) and send to the client the client will accept and then send regular MQTT keep-alive packets. 

### Device to cloud / Cloud to Device test
If you press 's' with focus on the client console, and have monitoring turned on in Device Explorer then you will see the message displayed in Device Explorer. If you select 'Messages to Device' in Device Explorer, enter a message and press 'Send' then you will see the message displayed on the Client Console Screen. If you press 'q' with Focus on the Client Console, then the client will send a graceful disconnect and terminate. 

### Azure Protocol Gateway DCM branch Console Screen
You will see the initial handshake as well keep-alive data coming in. You will also see device to cloud messages coming in and cloud to device messages being routed to the client. You will see 'encrypted' and 'clear' messages; both are the same message but one has the two's complement executed on it as a simple demo of a cryptographic algorithm (do not use in real scenarios)

# Step by Step - getting the project up and running
We will first setup the gateway then then client. Once both are configured you can then run gateway (it will connect to your IOT Hub) then the client and watch the interaction.

## Step One: install CMAKE
This is necessary for rebuilding the Azure C SDK. Version used for this code set: 3.7.2. You can download current from: [https://cmake.org/download/](https://cmake.org/download/)

## Step Two: Point local host to protocol-gateway.contoso.com
- Open an admin-level command prompt (or PowerShell)
- Navigate to c:\windows\system32\drivers\etc
- Open the hosts file in your favorite text editor. You will need admin rights to save this which is why we launched it as admin
- Enter: `127.0.0.1 protocol-gateway.contoso.com` and save the hosts file

## Step Three: Clone the Azure Protocol Gateway DCM branch to your local machine
- git clone https://github.com/jmarymee/azure-iot-protocol-gateway.git
- cd .\azure-iot-protocol-gateway
- git checkout dcm3

## Step Four: Setup an Azure IOT Hub
- Create or use an existing Azure IOT hub. In either case, copy the Primary Connection String. You will need this for the Azure Protocol Gateway AND the Device Explorer
- An IOT Hub Connection string looks like this: `HostName=APQIOTHub.azure-devices.net;SharedAccessKeyName=iothubowner;SharedAccessKey=tTT6HPC10RrjRH+WeJ/On71I3BnfnangV7WGfBZpgYk=`
- Create at least ONE device. You don't need to remember the name; we will get that PLUS a generated SAS string from Device Explorer

## Setp Five: Modify the Azure Protocol Gateway appSettings.config.user to point to your new Azure IOT Hub
- Navigate to .\azure-iot-protocol-gateway\host\ProtocolGateway.Host.Console
- Open the file `appSettings.config.user` in Visual Studio, VS Code or your favorite editor
- Modify the entry `<add key="IotHubClient.ConnectionString" value="REPLACE THIS WITH YOUR AZURE IOT CONNECTION STRING" />`  by replacing the example connection string with yours

That's it for the DCM Azure Protocol Gateway. When you run it locally, be sure to first launch the Azure Storage Emulator and have Visual Studio running with admin privileges.

## Step Six: Download and configure the uMQTT Client
There are two parts to the client; one is the uMQTT project (which is a fork of the Azure/Microsoft project) and the other is a github subproject called `azuresharedclientutility`. The uMqtt project could be used to connect to any valid MQTT server/endpoint but it's cloned here since it has properly configured (and working) parameters necessary to connect to an Azure IOT Hub. The `azuresharedclientutility` is where the magic happens.

- type `git clone --recursive https://github.com/jmarymee/azure-umqtt-c.git` (this will also clone down the azuresharedclientutility which points to the azure repo. We will fix this up)
- navigate to the directory `c-utility` under `azure-umqtt-c`. 
- Change the remote URL by typing `git remote set-url origin https://github.com/jmarymee/azure-c-shared-utility.git`
- type `git fetch`. This will obtain the branches from the fork with dcm versus the original pointer to the azure repo for `azuresharedclientutility`
- type `git checkout dcm3`
- Navigate to the parent (which is the parent repo) by typing `cd ..`
- type `git checkout dcm3`. This will checkout the dcm branch with the code changes. If you execute a `git status` everything should be nice and cleaner

## Step Seven: Build client solution files using cmake
The uMQTT client project uses CMAKE to generate solution files and project files for the client and azuresharedclientutility projects. Since they are generated by CMAKE there will be two references missing in the azuresharedclientutility project; specifically, the reference to the .c and .h files where the tls implementation exists. The files are pulled down when dcm3 was checked out, but we need to update the project file to reference them during the build.

- Open a Visual Studio Developer Command Prompt. We need to do this since CMAKE will refernce our compiler and build system
- Navigate to the .\azure-mqtt-c directory (the repo we cloned down in the last step)
- type `md cmake` (first we create a cmake directory)
- `cd cmake` and then type `cmake ..`. This will generate the project and solutions files. 

Now we need to fix up the visual studio project file for the aziotsharedutil.vcxproj file. We nust need to add two entries to the file list.

- From the cmake directory, navigate into the c-utility subdirectory. Type `cd c-utility`
- Open the file `aziotsharedutil.vcxproj` using your favorite text editor. Using Visual Studio code, you can type `code aziotsharedutil.vcxproj` to launch it
- Around line 308 you will see a file reference to the file `tlsio.h`. Copy the whole line (starting with `<ClInclude Include=`) and paste a copy immediately below it
- change the newly-copied entry from tlsio.h to `tlsio_dcm.h`.
- Further down, locate the line that references the `tlsio_schannel.c file`. It should be around line 355.
- Copy and paste immediately below the entry starting with `<ClCompile Include=`.
- Rename the file name `tlsio_schannel.c` in the newly-copied entry to `tlsio_dcm.c`

You've now updated the project file so we should now get a clean build.

- Save the `aziotsharedutil.vcxproj` file and exit your editor. 
- You should still be in the `cmake\c-utility` directory. Navigate up to the cmake directory. 
- You should still be in a Visual Studio Developer Command Prompt.
- Start a build by typing `cmake --build .` 

If all goes well, then you should get a clean build! You can also launch Visual Studio 2015 and open the solution file (located in the cmake directory). Once open you can rebuild/clean/rebuild successfully. Don't launch the client quite yet.

## Step Eight: Add your device parameters to the uMQTT sample. 
This is where we set the device name and access strings for the uMQTT client to access Azure IOT via the Azure Protocol Gateway. What the Gateway does is pass-through the device name and access strings to the Azure IOT endpoint in the cloud. At a deeper level, the client is communicating to the modified (DCM) Azure Protocol Gateway and then the gateway communicates to Azure IOT Hub using AMQP. 

- Open the client project is visual studio 2015. You can find the solution file name `umqtt.sln` in the cmake directory we created in the last step. 
- Expand the folder `uMQTT_Samples`. You should see the `mqtt_client_sample` project.
- Expand the project and then the `Source Files` tree
- Open the source file `mqtt_client_sample.c`
- Scroll / locate the function body for `void mqtt_client_sample_run()`

Starting at line 19, you will need to modify the TOPIC_SUB_NAME_A and TOPIC_NAMEA and TOPIC_NAMEB entries
- The example shows: 'devices/APQDevice/messages/events'. The second item betwee the forward slashes MUST match your device name
- Change the device-name portion of the TOPIC_SUB_NAME_A and TOPIC_NAME_A and TOPIC_NAME_B entries to match your device name. The device name is what you named your device in step 4

Starting at line 206, you will need to make some changes to make your Azure IOT connection work.
- Change the device name in line 206 `options.clientId =` to use your device name. The one present is `APQDevice`. The device name is what you named your device in Step Four. 
- Change the `options.username =` to point to your IOT hub and device. This a combination of the URL that points to your Azure IOT Hub, then the device name, then the API Version
- Open Azure IOT Device Explorer. If you haven't already done so, copy the Azure IOT Connection string for your IOT hub into the IOT Hub Connection String text box. This gives you access/views into your devices
- Click on Management
- Select your device. Then click on `SAS Token`
- Select a Time To Live (TTL). Ideally use 1 day or more
- Copy everything AFTER the `SharedAccessSignature=` part of the SAS. Somewhat confusing since `SharedAccessSignature` is stated twice. You want the second one and everything else that follows. That is your password. 
- For `options.password =` paste what you just copied. That is the password. 
- Around line 218 you may need to modify the value that is part of the line `TLSIO_CONFIG config = { "protocol-gateway.contoso.com", PORT_NUM_ENCRYPTED };` If you followed directions then you can leave this unmodified. 

>Side Note: The client needs to know where to find the gateway and needs to pass info so that the gateway knows where to route the message (where is the IOT Hub located by URL). This value `protocol-gateway.contoso.com` routes to localhost because we modified the host file on our local machine earlier. This makes dev/test easier since we can run both client and protocol gateway on one machine.

- Save the file and build.

## Step Nine: Run the Gateway and client locally
Now comes the fun part...will it work? We first will run the gateway and then the client. The client will look for the gateway, create a handshake and then start sending keep-alives. There are two commands you can type while the client is running and focus is on the command window for the client. 

- `s` Will send a canned message to the IOT Hub via the gateway. You can see the message on the command window opened for the running gateway
- `q` Will gracefully shut down the connection and terminate the client. 

Ok let's get this running
- Open Visual Studio 2015 with admin privilges. 
- Open the Azure Protocol Gateway Solution and build if necessary
- Run the Azure Storage Emulator. Be sure it's running before starting the gateway
- Under the `Host` folder in the Protocol Gateway project you will find the `ProtocolGateway.Host.Console` project. Right click, select `Debug` and `Start new instance`. If all goes  well will start and display messages on the output command window
- Open *another* instance of Visual Studio 2015 and open the umqtt solution under `azure-umqtt-c\cmake`
- Under the `uMQTT_Samples` folder, locate the `mqtt_client_sample` project, right-click and select `Debug` and `Start new instance`. 
- You should see it connect in the console/command window. If the code terminates then something was misconfigured

Now we can send/view message to/from the client using the Device Explorer
- With Device Explorer running, click on the tab labeled `Data`. 
- Make sure your Event Hub and Device ID are correct. 
- Click the check box for `Start time`
- Click the check box named `Enable` next to `Consumer Group`
- Click on `Monitor`
- Now if you press `s` with focus on the client console window then you will see it displayed in the `Event Hub Data` window

To send a message from Cloud to device:
- Select the tab named `Messages to Device` 
- In the `Message` box, enter a string
- Click the `Send` button. You should see the message appear in both the Protocol Gateway console output AND the client Console output

Congratulations! You have now connected an MQTT client to Azure IOT via a Protocol Gateway with a custom TLS provider.

# Common Issues
1) Client SAS Expiration. The MQTT client performs a pass-through authentication to the IOT Hub via the Gateway using a name and password. The password is a SAS token generated using Device Explorer or perhaps programmatically. They are usually life-limited. If they expire then you will see the client connect to the Gateway (in the console screen) but then fail. That's due to the IOT Hub rejecting the SAS. The solution is to generate a new SAS and paste it into the MQTT client sample. Compile and run and all should be fine 
