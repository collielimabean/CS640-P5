package edu.wisc.cs.sdn.simpledns;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import edu.wisc.cs.sdn.simpledns.packet.DNS;
import edu.wisc.cs.sdn.simpledns.packet.DNSQuestion;
import edu.wisc.cs.sdn.simpledns.packet.DNSRdataAddress;
import edu.wisc.cs.sdn.simpledns.packet.DNSRdataString;
import edu.wisc.cs.sdn.simpledns.packet.DNSResourceRecord;

public class DNSServer implements AutoCloseable, Runnable
{
    private static final int DNS_SERVER_PORT = 8053;
    private static final int DNS_PORT = 53;
    private DatagramSocket socket;
    private InetAddress rootDNS;
    private Map<String, String> ec2Map;
    
    public DNSServer(InetAddress root, File ec2) throws SocketException, IOException
    {
        ec2Map = new HashMap<String, String>();
        socket = new DatagramSocket(DNS_SERVER_PORT);
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
    
    public void run()
    {
        while (true)
        {
            try
            {
                byte[] buffer = new byte[1024];
                DatagramPacket pkt = new DatagramPacket(buffer, buffer.length);
                
                while (true)
                {
                    System.out.println("Listening for packets...");
                    socket.receive(pkt);
                    DNS dns = DNS.deserialize(pkt.getData(), pkt.getData().length);
                    if (dns.getOpcode() == DNS.OPCODE_STANDARD_QUERY)
                        processQuery(dns, pkt.getAddress(), pkt.getPort());
                }
            }
            catch (IOException e)
            {
                e.printStackTrace();
            }
        }
    }
    
    public void processQuery(DNS pkt, InetAddress origIp, int origPort) throws IOException
    {
        if (pkt.getOpcode() != DNS.OPCODE_STANDARD_QUERY)
            return;
        
        if (pkt.getQuestions().isEmpty())
        {
            System.out.println("DNS Query received with no questions, dropping.");
            return;
        }
        
        // if no recursion, then just forward the packet
        if (!pkt.isRecursionDesired())
        {
            DNS response = this.handleNonRecursive(pkt);
            System.out.println("Non recursive: Received a response! Forwarding!");
            this.sendDNSPkt(response, origIp, origPort);
            return;
        }
        
        for (DNSQuestion question : pkt.getQuestions())
        {
            switch (question.getType())
            {
                case DNS.TYPE_A:
                case DNS.TYPE_AAAA:
                case DNS.TYPE_CNAME:
                case DNS.TYPE_NS:
                    DNS resolved = handleRecursive(pkt);
                    this.sendDNSPkt(resolved, origIp, origPort);
                    return;
                default:
                    continue;
            }
        }
    }

    private void sendDNSPkt(DNS dns, InetAddress addr, int port) throws IOException
    {
        byte[] serialized = dns.serialize();
        DatagramPacket p = new DatagramPacket(serialized, serialized.length, addr, port);
        socket.send(p);
    }
    
    /* 
     * Implementation for handling multiple questions is not required
     * For cases where you get Authority Sections without Additional sections. 
     * You should recursively fetch the IP for the name server in the Authority Section. 
     * Once you get one of the name servers IP in this authority list, you can continue with the name resolution of the orignial query.
     */
    
    private DNS handleRecursive(DNS query) throws IOException
    {
        // DNSQuestion in question //
        DNSQuestion question = query.getQuestions().get(0);
        
        // send query to root //
        DNS dns = new DNS();
        dns.setOpcode(DNS.OPCODE_STANDARD_QUERY);
        //dns.setId(query.getId());
        dns.setQuery(true);
        dns.setTruncated(true);
        dns.setAuthenicated(false);
        dns.setRecursionDesired(true);
        dns.addQuestion(question); // only handle first question
        this.sendDNSPkt(dns, rootDNS, DNS_PORT);
        
        // required state variables //
        boolean done = false;
        DNSQuestion cnameQuestion = null;
        DNSResourceRecord cnameRecord = null;
        
        while (!done)
        {
            // parse root response //
            byte[] recv = new byte[1024];
            DatagramPacket recvPkt = new DatagramPacket(recv, recv.length);
            socket.receive(recvPkt);
            DNS rootResponse = DNS.deserialize(recvPkt.getData(), recvPkt.getLength());
            System.out.println("Root returned: " + rootResponse);
            
            List<DNSResourceRecord> rootAnswers = rootResponse.getAnswers();
            if (rootAnswers.isEmpty())
            {
                System.out.println("RootAnswers is empty!");
                // if original query was NS, then done!
                if (question.getType() == DNS.TYPE_NS)
                {
                    DNS clientResponse = new DNS();
                    clientResponse.setOpcode(DNS.OPCODE_STANDARD_QUERY);
                    clientResponse.setQuery(false);
                    clientResponse.setRcode(DNS.RCODE_NO_ERROR);
                    clientResponse.setAuthorities(rootResponse.getAuthorities());
                    clientResponse.setRecursionAvailable(true);
                    clientResponse.setRecursionDesired(true);
                    clientResponse.setAuthoritative(false);
                    clientResponse.setAuthenicated(false);
                    clientResponse.setCheckingDisabled(false);
                    clientResponse.setTruncated(false);
                    
                    System.out.println("Handled client DNS NS query");
                    
                    clientResponse.setQuestions(rootResponse.getQuestions());
                    clientResponse.setAnswers(rootResponse.getAdditional());
                    return clientResponse;
                }
                
                // not NS - look for other name servers to query //
                for (DNSResourceRecord auth : rootResponse.getAuthorities())
                {
                    boolean found = false;
                    for (DNSResourceRecord addl : rootResponse.getAdditional())
                    {
                        if ((addl.getType() == DNS.TYPE_A || addl.getType() == DNS.TYPE_AAAA)
                            && (auth.getType() == DNS.TYPE_NS))
                        {
                            // forward query to this new nameserver //
                            InetAddress nextAddr = ((DNSRdataAddress)addl.getData()).getAddress();
                            System.out.println("Querying new NS: " + nextAddr.toString());
                            this.sendDNSPkt(dns, nextAddr, DNS_PORT);
                            
                            found = true;
                            break;
                        }
                    }
                    
                    if (found)
                        break;
                }
                // back to listening //
            }
            else
            {
                // check if we are done //
                DNSResourceRecord rootAnswer = rootResponse.getAnswers().get(0);
                DNSQuestion rootQuestion = rootResponse.getQuestions().get(0);

                // if CNAME, continue resolution //
                if (rootAnswer.getType() == DNS.TYPE_CNAME)
                {
                    // save this record, we'll need it when resolution is complete //
                    cnameRecord = rootAnswer;
                    cnameQuestion = rootQuestion;
                    
                    DNS nextQuery = new DNS();
                    nextQuery.setId(query.getId());
                    nextQuery.setOpcode(DNS.OPCODE_STANDARD_QUERY);
                    nextQuery.setQuery(true);
                    nextQuery.setTruncated(true);
                    nextQuery.setAuthenicated(false);
                    nextQuery.setRecursionDesired(true);
                    
                    // create question with last answer data
                    DNSQuestion nextQuestion = new DNSQuestion(rootAnswer.getName(), rootQuestion.getType());
                    nextQuery.addQuestion(nextQuestion); 
                    
                    this.sendDNSPkt(nextQuery, rootDNS, DNS_PORT);
                    continue;
                }

                // we are done, prepare to echo back to client //
                DNS clientResponse = new DNS();
                clientResponse.setOpcode(DNS.OPCODE_STANDARD_QUERY);
                clientResponse.setQuery(false);
                clientResponse.setRcode(DNS.RCODE_NO_ERROR);
                clientResponse.setAuthorities(rootResponse.getAuthorities());
                clientResponse.setRecursionAvailable(true);
                clientResponse.setRecursionDesired(true);
                clientResponse.setAuthoritative(false);
                clientResponse.setAuthenicated(false);
                clientResponse.setCheckingDisabled(false);
                clientResponse.setTruncated(false);
                
                clientResponse.addQuestion(rootQuestion);
                clientResponse.addQuestion(cnameQuestion);
                clientResponse.addAnswer(rootAnswer);
                clientResponse.addAnswer(cnameRecord);
                
                // type A needs the ec2 stuff //
                if (rootQuestion.getType() == DNS.TYPE_A)
                {
                    for (Map.Entry<String, String> pair : this.ec2Map.entrySet())
                    {
                        String map_ip = pair.getKey();
                        String map_region = pair.getValue();
                        for (DNSResourceRecord record : rootResponse.getAnswers())
                        {
                            String record_ip = record.getData().toString();
                            if (!map_ip.equals(record_ip))
                                continue;
                            
                            DNSResourceRecord txtRecord = new DNSResourceRecord();
                            txtRecord.setTtl(100);
                            txtRecord.setType(DNS.TYPE_EC2);
                            txtRecord.setName(record.getName());
                            
                            DNSRdataString data = new DNSRdataString();
                            data.setString(map_region + "-" + map_ip);
                            
                            txtRecord.setData(data);
                            
                            System.out.println("Resolved EC2: " + data);
                            clientResponse.addAnswer(txtRecord);
                        }
                    }
                }
                
                return clientResponse;
            }
        }
        
        // error //
        return null;
    }
    
    private DNS handleNonRecursive(DNS query) throws IOException
    {
        this.sendDNSPkt(query, this.rootDNS, DNS_PORT);
        
        byte[] recv = new byte[1024];
        DatagramPacket recvPkt = new DatagramPacket(recv, recv.length);
        socket.receive(recvPkt);
        return DNS.deserialize(recvPkt.getData(), recvPkt.getData().length);
    }
    
    @Override
    public void close() throws Exception
    {
        socket.close();
    }
}
