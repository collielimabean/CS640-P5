package edu.wisc.cs.sdn.simpledns;

import java.io.File;
import java.net.InetAddress;
import java.net.UnknownHostException;

public class SimpleDNS 
{
	public static void main(String[] args) throws Exception
	{
	    InetAddress root_dns_ip = null;
	    File ec2_csv = null;
	    
	    // parse command line arguments //
	    for (int i = 0; i < args.length; i++)
	    {
	        switch (args[i])
	        {
	            case "-r":
	                if (i + 1 >= args.length)
	                    break;
	                
	                try
                    {
	                    root_dns_ip = InetAddress.getByName(args[i + 1]);
                    }
                    catch (UnknownHostException e)
                    {
                        System.err.println("Invalid IP Address supplied!");
                        break;
                    }
	                break;
	                
	            case "-e":
	                if (i + 1 >= args.length)
                        break;
	                
	                ec2_csv = new File(args[i + 1]);
                    break;
                    
                default:
                    break;
	        }
	    }
	    
	    // parse failure //
	    if (root_dns_ip == null || ec2_csv == null || !ec2_csv.exists())
            return;
	    
	    System.out.println("SimpleDNS server started.");
	    
	    // run state machine //
	    try (DNSServer server = new DNSServer(root_dns_ip, ec2_csv))
	    {
            server.run();
	    }
	}
}
