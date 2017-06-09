using System;
using System.Collections.Generic;
using SharpPcap;
using PacketDotNet.LLDP;
using System.Net;




namespace lldp
{
    class Program
    {

        static void Main(string[] args)
        {
            // Print version
            string build = "1";
            string ver = SharpPcap.Version.VersionString;
            Console.WriteLine("LLDPspy build {0} using lib v{1} 2017 M.Götze\n", build, ver);

            // Retrieve the device list
            // TODO: add try
            try
            {
                var devices = CaptureDeviceList.Instance;
                // If no devices were found print an error
                if (devices.Count < 1)
                {
                    Console.WriteLine("Sorry, can't continue, no usable devices were found on this machine!\n");
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
                        Console.WriteLine("{0}) {1}", x, dev.Description);
                        ix_map[x] = i;
                        x++;
                    }
                    i++;
                }
                if (x < 1)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("No useable Adapter found!");
                    Console.ForegroundColor = ConsoleColor.White;
                    Environment.Exit(1);
                }
                else if (x > 1)
                {
                    // Selection because > 1
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

                Console.WriteLine();
                //Console.WriteLine("-- The following tcpdump filter will be applied: \"{0}\"",filter);
                Console.WriteLine
                    ("-- Listening on {0}, hit 'Ctrl-C' to exit...",
                    device.Description);

                // Start capture packets
                device.Capture();

                // Close the pcap device
                // (Note: this line will never be called since
                //  we're capturing infinite number of packets
                device.Close();
            } catch
            {
                Console.WriteLine("WinPCAP library is missing, please install from: https://www.winpcap.org\n");
                Environment.Exit(1);
            }

           
       }

        

        /// <summary>
        /// Prints the time and length of each received packet
        /// </summary>
        private static void device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            var time = DateTime.Now;
            var len = e.Packet.Data.Length;
            var packet = PacketDotNet.Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            var LLDPPacket = (PacketDotNet.LLDPPacket)packet.Extract(typeof(PacketDotNet.LLDPPacket));
            if (LLDPPacket != null)
            {
                //  TLVs={ChassisID|PortID|TimeToLive|PortDescription|SystemName|SystemDescription|SystemCapabilities|ManagementAddress|OrganizationSpecific|OrganizationSpecific|EndOfLLDPDU}
                int TLVs = Convert.ToInt16(LLDPPacket.TlvCollection.Count.ToString());
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("{0}:{1}:{2} LLDP Packet received with {5} TLVs",
                time.Hour, time.Minute, time.Second, time.Millisecond, len, TLVs);
                Console.ForegroundColor = ConsoleColor.White;
                foreach (TLV tlv in LLDPPacket.TlvCollection)
                {
                    //Console.WriteLine("Type: " + tlv.GetType().ToString()); // + "=\t" + tlv.ToString());
                            // PacketDotNet.LLDP.PortDescription
                            if (tlv.GetType().Equals(typeof(PortDescription)))
                            {
                                Console.ForegroundColor = ConsoleColor.Cyan;
                                Console.WriteLine("Port: " + ((PortDescription)tlv).Description );
                                Console.ForegroundColor = ConsoleColor.White;
                            }
                            if (tlv.GetType().Equals(typeof(SystemName)))
                            {
                                Console.WriteLine(((SystemName)tlv).Name );
                            }
                            if (tlv.GetType().Equals(typeof(SystemDescription)))
                            {
                                Console.ForegroundColor = ConsoleColor.Gray;
                                Console.WriteLine(((SystemDescription)tlv).Description);
                                Console.ForegroundColor = ConsoleColor.White;
                            }
                            if (tlv.GetType().Equals(typeof(OrganizationSpecific)))
                            {
                               // Console.WriteLine("\tO:\t" + ((OrganizationSpecific)tlv).OrganizationDefinedSubType.ToString());
                            }
                }

            }

        }

    }
}

