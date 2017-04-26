package edu.wisc.cs.sdn.simpledns;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.util.Map;

import edu.wisc.cs.sdn.simpledns.packet.DNS;
import edu.wisc.cs.sdn.simpledns.packet.DNSQuestion;

public class DNSServer implements AutoCloseable
{
    private static final int DNS_PORT = 8053;
    private DatagramSocket socket;
    private InetAddress rootDNS;
    private Map<String, String> ec2Map;
    
    public DNSServer(InetAddress root, File ec2) throws SocketException, IOException
    {
        socket = new DatagramSocket(DNS_PORT);
        rootDNS = root;
        
        // parse ec2 file //
        BufferedReader br = new BufferedReader(new FileReader(ec2));
        String line;
        while ((line = br.readLine()) != null)
        {
            String[] items = line.split(",");
            if (items.length != 2)
                continue;
            
            String ip = items[0].substring(0, items[0].indexOf('/'));
            ec2Map.put(ip, items[1]);
        }
        
        br.close();
    }
    
    public DNS getQueryFromClient() throws IOException
    {
        byte[] buffer = new byte[1024];
        DatagramPacket pkt = new DatagramPacket(buffer, buffer.length);
        
        while (true)
        {
            socket.receive(pkt);
            DNS dns = DNS.deserialize(pkt.getData(), pkt.getData().length);
            if (dns.getOpcode() == DNS.OPCODE_STANDARD_QUERY)
                return dns;
        }
    }
    
    public void processQuery(DNS pkt)
    {
        if (pkt.getOpcode() != DNS.OPCODE_STANDARD_QUERY)
            return;
        
        for (DNSQuestion question : pkt.getQuestions())
        {
            switch (question.getType())
            {
                case DNS.TYPE_A:
                    // send query to root dns (ipv4)
                case DNS.TYPE_AAAA:
                    // send query to root dns (ipv6)
                case DNS.TYPE_CNAME:
                    // (alias)
                case DNS.TYPE_NS:
                    // 
                default:
                    continue;
            }
        }
    }

    /* 
     * Implementation for handling multiple questions is not required
     * For cases where you get Authority Sections without Additional sections. 
     * You should recursively fetch the IP for the name server in the Authority Section. 
     * Once you get one of the name servers IP in this authority list, you can continue with the name resolution of the orignial query.
     */
    
    private void  handleAType(DNSQuestion origQuestion, boolean recurse) throws IOException
    {
        // send query to root //
        DNS dns = new DNS();
        dns.addQuestion(new DNSQuestion(origQuestion.getName(), origQuestion.getType()));
        
        byte[] serialized = dns.serialize();
        DatagramPacket p = new DatagramPacket(serialized, serialized.length);
        p.setAddress(rootDNS);
        p.setPort(DNS_PORT);
        socket.send(p);
        
        // receive & parse response //
    }
    
    @Override
    public void close() throws Exception
    {
        socket.close();
    }
}
