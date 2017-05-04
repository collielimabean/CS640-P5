package edu.wisc.cs.sdn.simpledns;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

import edu.wisc.cs.sdn.simpledns.packet.DNS;
import edu.wisc.cs.sdn.simpledns.packet.DNSQuestion;
import edu.wisc.cs.sdn.simpledns.packet.DNSRdataAddress;
import edu.wisc.cs.sdn.simpledns.packet.DNSRdataName;
import edu.wisc.cs.sdn.simpledns.packet.DNSRdataString;
import edu.wisc.cs.sdn.simpledns.packet.DNSResourceRecord;

public class DNSServer implements AutoCloseable, Runnable
{
    private class Subnet
    {
        String ec2_text;
        String readable_subnet;
        int subnet;
        int prefix;

        public Subnet(String ec2_text, String cidr) throws UnknownHostException
        {
            String[] split = cidr.split("/");
            byte[] ip_bytes = InetAddress.getByName(split[0]).getAddress();
            this.readable_subnet = split[0];
            this.subnet = (ip_bytes[0] << 24) | (ip_bytes[1] << 16) | (ip_bytes[2] << 8) | ip_bytes[3];
            this.prefix = Integer.parseInt(split[1]);
            this.ec2_text = ec2_text;
        }

        public boolean isMatch(String ip) throws UnknownHostException
        {
            byte[] ip_bytes = InetAddress.getByName(ip).getAddress();
            int conv_ip = (ip_bytes[0] << 24) | (ip_bytes[1] << 16) | (ip_bytes[2] << 8) | ip_bytes[3];
            int mask = (~0) << (32 - this.prefix);
            return (subnet & mask) == (conv_ip & mask);
        }
    }
    
    private static final int DEFAULT_TTL = 3600; // 1 hr
    private static final int DNS_SERVER_PORT = 8053;
    private static final int DNS_PORT = 53;
    private DatagramSocket socket;
    private InetAddress rootDNS;
    private List<Subnet> ec2List; // ip to subnet
    
    public DNSServer(InetAddress root, File ec2) throws SocketException, IOException
    {
        ec2List = new ArrayList<Subnet>();
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
            
            ec2List.add(new Subnet(items[1], items[0]));
        }
        
        br.close();
    }
    
    public void run()
    {
        while (true)
        {
            try
            {
                byte[] buffer = new byte[4096];
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
    
    private DNS handleRecursive(DNS query) throws IOException
    {
        // DNSQuestion in question //
        DNSQuestion question = query.getQuestions().get(0);
        
        // send query to root //
        this.sendDNSPkt(query, rootDNS, DNS_PORT);
        
        // required state variables //
        boolean done = false;
        List<DNSResourceRecord> cnameList = new ArrayList<DNSResourceRecord>();
        List<DNSResourceRecord> authList = new ArrayList<DNSResourceRecord>();
        List<DNSResourceRecord> addlList = new ArrayList<DNSResourceRecord>();
        
        while (!done)
        {
            // receive data //
            byte[] recv = new byte[1024];
            DatagramPacket recvPkt = new DatagramPacket(recv, recv.length);
            socket.receive(recvPkt);
            
            // parse packet //
            DNS rootResponse = DNS.deserialize(recvPkt.getData(), recvPkt.getLength());
            System.out.println("Root returned: " + rootResponse);
            
            // parsed packet variables //
            List<DNSResourceRecord> rootAnswers = rootResponse.getAnswers();
            List<DNSResourceRecord> rootAuthorities = rootResponse.getAuthorities();
            List<DNSResourceRecord> rootAdditional = rootResponse.getAdditional();
            
            // check if authorities section is not SOA (start of authority) //
            
            boolean is_soa = true;
            for (DNSResourceRecord dr : rootAuthorities)
            {
                switch (dr.getType())
                {
                    case DNS.TYPE_A:
                    case DNS.TYPE_AAAA:
                    case DNS.TYPE_NS:
                    case DNS.TYPE_CNAME:
                        is_soa = false;
                        break;
                }
            }
            
            // this is a non empty auth list, save it //
            if (!is_soa)
                authList = rootAuthorities;
            
            if (!rootAdditional.isEmpty())
                addlList = rootAdditional;
            
            if (rootAnswers.isEmpty())
            {
                System.out.println("RootAnswers is empty!");
                
                // if original query was NS, then done!
                if (question.getType() == DNS.TYPE_NS)
                {
                    DNS clientResponse = this.createDNSReply();
                    
                    System.out.println("Handled client DNS NS query");
                    
                    clientResponse.setQuestions(rootResponse.getQuestions());
                    clientResponse.setAnswers(rootResponse.getAdditional());
                    return clientResponse;
                }
                
                // not NS - look for other name servers to query //
                for (DNSResourceRecord authRecord : rootAuthorities)
                {
                    if (authRecord.getType() != DNS.TYPE_NS)
                        continue;
                    
                    boolean found = false;
                    DNSRdataName nsName = (DNSRdataName) authRecord.getData();
                    
                    for (DNSResourceRecord addlRecord: rootResponse.getAdditional())
                    {
                        if (addlRecord.getType() == DNS.TYPE_A && nsName.getName().equals(addlRecord.getName()))
                        {
                            // forward query to this new nameserver //
                            InetAddress nextAddr = ((DNSRdataAddress)addlRecord.getData()).getAddress();
                            System.out.println("Querying new NS: " + nextAddr.toString());
                            this.sendDNSPkt(query, nextAddr, DNS_PORT);
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
                System.out.println("Answers detected");
                // check if we are done //
                DNSResourceRecord rootAnswer = rootResponse.getAnswers().get(0);

                // if CNAME, continue resolution //
                if (rootAnswer.getType() == DNS.TYPE_CNAME)
                {
                    System.out.println("CNAME detected " + rootAnswer);
                    // save this record, we'll need it when resolution is complete //
                    cnameList.add(rootAnswer);
                    
                    // prepare query //
                    DNS nextQuery = this.createDNSRequest();
                    nextQuery.setId(query.getId());
                    
                    // create question with last answer data //
                    DNSQuestion nextQuestion = new DNSQuestion();
                    DNSRdataName dnsRdataname = (DNSRdataName) rootAnswer.getData();
                    nextQuestion.setName(dnsRdataname.getName());
                    nextQuestion.setType(question.getType());
                    
                    // add question to query //
                    nextQuery.addQuestion(nextQuestion);
                    
                    // send it out //
                    this.sendDNSPkt(nextQuery, rootDNS, DNS_PORT);
                    continue;
                }

                // we are done, prepare to echo back to client //
                DNS clientResponse = this.createDNSReply();
                
                List<DNSResourceRecord> responseAnswers = new ArrayList<DNSResourceRecord>(rootAnswers);
                
                // add any necessary TXT records //
                if (question.getType() == DNS.TYPE_A)
                {
                    for (DNSResourceRecord answer : rootAnswers)
                    {
                        if (answer.getType() != DNS.TYPE_A)
                            continue;
                        
                        for (Subnet s : this.ec2List)
                        {
                            DNSRdataAddress answerData = (DNSRdataAddress) answer.getData();
                            
                            // match found, add TXT record //
                            if (s.isMatch(answerData.getAddress().toString().replace("/", "")))
                            {
                                DNSResourceRecord txtRecord = new DNSResourceRecord();
                                txtRecord.setType(DNS.TYPE_TXT);
                                txtRecord.setName(answer.getName());
                                txtRecord.setTtl(DEFAULT_TTL);
                                
                                DNSRdataString txt = new DNSRdataString(s.ec2_text + "-" + s.readable_subnet);
                                txtRecord.setData(txt);
                                
                                responseAnswers.add(txtRecord);
                                break;
                            }
                        }
                    }
                }
                
                // add resolved CNAMEs to the front of the list //
                for (DNSResourceRecord cnameRecord : cnameList)
                    responseAnswers.add(0, cnameRecord);
                
                // pop in appropriate authority & additional sections //
                if (rootAuthorities.isEmpty())
                    clientResponse.setAuthorities(authList);
                else
                    clientResponse.setAuthorities(rootAuthorities);
                
                if (rootAdditional.isEmpty())
                    clientResponse.setAdditional(addlList);
                else
                    clientResponse.setAdditional(rootAdditional);
                
                // set answers & questions //
                clientResponse.setId(query.getId());
                clientResponse.setAnswers(responseAnswers);
                clientResponse.setQuestions(query.getQuestions());
                
                return clientResponse;
            }
        }
        
        // error //
        return null;
    }
    
    private DNS handleNonRecursive(DNS query) throws IOException
    {
        this.sendDNSPkt(query, this.rootDNS, DNS_PORT);
        
        byte[] recv = new byte[4096];
        DatagramPacket recvPkt = new DatagramPacket(recv, recv.length);
        socket.receive(recvPkt);
        return DNS.deserialize(recvPkt.getData(), recvPkt.getData().length);
    }
    
    @Override
    public void close() throws Exception
    {
        socket.close();
    }
    
    private DNS createDNSRequest()
    {
        DNS dns = new DNS();
        dns.setQuery(true);
        dns.setOpcode(DNS.OPCODE_STANDARD_QUERY);
        dns.setTruncated(false);
        dns.setRecursionDesired(true);
        dns.setAuthenicated(false);
        return dns;
    }
    
    private DNS createDNSReply()
    {
        DNS dns = new DNS();
        dns.setQuery(false);
        dns.setOpcode(DNS.OPCODE_STANDARD_QUERY);
        dns.setAuthoritative(false);
        dns.setTruncated(false);
        dns.setRecursionAvailable(true);
        dns.setRecursionDesired(true);
        dns.setAuthenicated(false);
        dns.setCheckingDisabled(false);
        dns.setRcode(DNS.RCODE_NO_ERROR);
        return dns;
    }
}
