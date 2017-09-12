using System;
using System.Collections.Generic;
using SharpPcap;
using PacketDotNet.LLDP;
using System.Net;




namespace lldp
{
    class Program
    {
        static bool opt_json = false;
        static bool opt_quit = false;


        static void Main(string[] args)
        {


            // Check commandline
            if (args.Length > 0)
            {
                foreach (string arg in args)
                {
                    lldp.Program.opt_json = lldp.Program.opt_json || arg == "/j";
                    lldp.Program.opt_quit = lldp.Program.opt_quit || arg == "/q";
                }
            }
            
            

            // Print version
            string build = "2017-09-12";
            string ver = SharpPcap.Version.VersionString;
            if (opt_json != true)
            {
                Console.WriteLine("LLDPspy build {0} using lib v{1} 2017 Marco Götze, planetlan\n", build, ver);
                Console.WriteLine("\n\n\toptional parameters:\n");
                Console.WriteLine("\t/j\tOutput as JSON string\n\t/q\tQuit after first TLV received\n\n\tBest Usage for reuse of information lldp /j /q\n\n");
            }
            //if (opt_json == true) Console.WriteLine("JSON");
            //if (opt_quit == true) Console.WriteLine("QUIT");
            // Retrieve the device list
            // TODO: add try
            try
            {
                var devices = CaptureDeviceList.Instance;
                // If no devices were found print an error
                if (devices.Count < 1)
                {
                    if (opt_json == true)   Console.WriteLine("{\"error\":\"no usable devices found\",\"number\": 1}");
                    else                    Console.WriteLine("ERROR 1: Sorry, can't continue, no usable devices were found on this machine!\n");
                    return;
                }
                // Mapping so we only get used interfaces not filtered
                int i = 0;
                int x = 0;
                int[] ix_map = new int[devices.Count];


                // Scan the list printing every entry
                foreach (var dev in devices)
                {
                    // Filter Devices we don't want
                    if (dev.Description.Contains("TAP") == false
                        && dev.Description.Contains("Oracle") == false
                        && dev.Description.Contains("Virtual") == false
                        && dev.Description.Contains("VPN") == false
                        && dev.Description.Contains("'Microsoft'") == false
                        && dev.Description.Contains("loop") == false)
                    {
                        if (opt_json != true) Console.WriteLine("{0}) {1}", x, dev.Description);
                        ix_map[x] = i;
                        x++;
                    }
                    i++;
                }
                if (x < 1)
                {
                    if (opt_json == true) Console.WriteLine("{\"error\":\"no usable adapter found\",\"number\": 2}");
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("No useable Adapter found!");
                        Console.ForegroundColor = ConsoleColor.White;
                        Environment.Exit(1);
                    }
                        
                }
                else if (x > 1)
                {
                    // Selection because > 1
                    if (opt_json == true)
                    {
                        x = 0;
                    }
                    else
                    {
                        Console.WriteLine("Found: " + x.ToString());
                        Console.WriteLine();
                        Console.Write("your choice? ");
                        if (int.TryParse(Console.ReadLine(), out x))
                        {
                            // ok 
                        }
                        else
                        {
                            Console.WriteLine("Sorry, invalid Input!\n");
                        }
                    }
                    
                }
                else
                {
                    x = 0;
                }

                i = ix_map[x];
                var device = devices[i];
                //Register our handler function to the 'packet arrival' event
                device.OnPacketArrival +=
                new PacketArrivalEventHandler(device_OnPacketArrival);

                //Open the device for capturing
                int readTimeoutMilliseconds = 1000;
                device.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);

                // tcpdump filter to capture only TCP/IP packets for LLDP and CDP
                string filter = "ether[12:2]=0x88cc or ether[20:2]=0x2000";
                device.Filter = filter;
                if (opt_json != true)
                {
                    Console.WriteLine();
                    //Console.WriteLine("-- The following tcpdump filter will be applied: \"{0}\"",filter);
                    Console.WriteLine("-- Listening on {0}, hit 'Ctrl-C' to exit...", device.Description);
                }
                    
                // Start capture packets
                device.Capture();

                // Close the pcap device
                // (Note: this line will never be called since
                //  we're capturing infinite number of packets
                device.Close();
            } catch (Exception e)
            {
                if (opt_json == true) Console.WriteLine("{\"error\":\""+e.ToString()+"\",\"number\": 999}");
                else
                {
                    Console.WriteLine("WinPCAP library is missing, please install from:");
                    Console.WriteLine("\twin10x64:\twww.win10pcap.org\n");
                    Console.WriteLine("\tother:\thttps://www.winpcap.org\n");
                    Environment.Exit(1);
                }
            }

           
       }

        static string clean4json(string payload)
        {
            payload.Replace("\"", "");
            payload.Replace("\n", " ");
            payload.Replace("'", "");
            payload.Replace("\r", "");
            return payload.Trim();
        }

        /// <summary>
        /// Prints the time and length of each received packet
        /// </summary>
        static void device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            var time = DateTime.Now;
            var len = e.Packet.Data.Length;
            var packet = PacketDotNet.Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            var LLDPPacket = (PacketDotNet.LLDPPacket)packet.Extract(typeof(PacketDotNet.LLDPPacket));
            string[] results = new string[5];// 0: TLVs, 1: name, 2: port, 3: description, 4: chassisID
            results[0] = ""; // TLVs
            results[1] = ""; // name
            results[2] = ""; // port
            results[3] = ""; // desciption
            results[4] = ""; // chassisid
 
 
            if (LLDPPacket != null)
            {
                //  TLVs={ChassisID|PortID|TimeToLive|PortDescription|SystemName|SystemDescription|SystemCapabilities|ManagementAddress|OrganizationSpecific|OrganizationSpecific|EndOfLLDPDU}
                int TLVs = Convert.ToInt16(LLDPPacket.TlvCollection.Count.ToString());
                
                if(lldp.Program.opt_json != true)
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("{0}:{1}:{2} LLDP Packet received with {5} TLVs",
                    time.Hour, time.Minute, time.Second, time.Millisecond, len, TLVs);
                    //results[0] = TLVs.ToString();
                    Console.ForegroundColor = ConsoleColor.White;
                }
                
                foreach (TLV tlv in LLDPPacket.TlvCollection)
                {
                    //Console.WriteLine("Type: " + tlv.GetType().ToString()); // + "=\t" + tlv.ToString());
                    // PacketDotNet.LLDP.PortDescription
                    /*Console.WriteLine(tlv.GetType().ToString());
                    if (tlv.GetType().Equals(typeof(OrganizationSpecific)))
                    {
                        Console.ForegroundColor = ConsoleColor.Cyan;
                        Console.WriteLine("o: " + ((OrganizationSpecific)tlv).ToString());
                        Console.ForegroundColor = ConsoleColor.White;
                    }
                    */
                            // MAC Switch
                            if (tlv.GetType().Equals(typeof(ChassisID)))
                            {
                                if (opt_json != true)
                                {
                                    Console.ForegroundColor = ConsoleColor.Cyan;
                                    Console.WriteLine("ChassisID: " + ((ChassisID)tlv).ToString());
                                    //Console.WriteLine("ChassisID: " +  ChassisSubTypes.MACAddress.ToString());
                                    Console.ForegroundColor = ConsoleColor.White;
                                }
                                results[4] = clean4json(((ChassisID)tlv).ToString());
                            }
                            /*if (tlv.GetType().Equals(typeof(PortID)))
                            {
                                Console.ForegroundColor = ConsoleColor.Cyan;
                                Console.WriteLine("PortID: " + ((PortID)tlv).ToString());
                                Console.ForegroundColor = ConsoleColor.White;
                            }*/
                            if (tlv.GetType().Equals(typeof(PortDescription)))
                            {
                                //Console.ForegroundColor = ConsoleColor.Cyan;
                                if (opt_json != true) Console.WriteLine("Port: " + ((PortDescription)tlv).Description );
                                results[2] = clean4json(((PortDescription)tlv).Description.ToString().Trim());
                                //Console.ForegroundColor = ConsoleColor.White;
                            }
                            if (tlv.GetType().Equals(typeof(SystemName)))
                            {
                                if(opt_json != true) Console.WriteLine("Name: " + ((SystemName)tlv).Name );
                                results[1] = clean4json(((SystemName)tlv).Name.ToString().Trim());
                            }
                            if (tlv.GetType().Equals(typeof(SystemDescription)))
                            {
                                /*
                                Console.ForegroundColor = ConsoleColor.Gray;
                                Console.WriteLine("Description: " + ((SystemDescription)tlv).Description);
                                Console.ForegroundColor = ConsoleColor.White;
                                */
                                results[3] = clean4json(((SystemDescription)tlv).Description.ToString());
                            }
                            if (tlv.GetType().Equals(typeof(OrganizationSpecific)))
                            {
                               //Console.WriteLine("\tO:\t" + ((OrganizationSpecific)tlv).OrganizationDefinedSubType.ToString());
                            }
                            

                }
                // Checking if all neccessary information is present, then quit.
                if (results[1] != "" && results[2] != "")
                {
                    if (opt_json == true)
                    {
                        Console.WriteLine("{\"name\":\"" + results[1] + "\",\"port\":\"" + results[2] + "\",\"description\":\"" + results[3] + "\",\"chassisid\":\"" + results[4] + "\"}");
                    }
                    if (opt_quit == true) Environment.Exit(1);
                }
            }

        }

    }
}

