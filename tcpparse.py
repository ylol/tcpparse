#!/usr/bin/python

import dpkt
import sys

class stat:
    

    def __init__(self, ts_f, ts_l, pc, t, so, sa, i):
       self.first_ts = ts_f
       self.last_ts = ts_l
       self.packet_count = pc
       self.totalbytes = t
       self.synonly = so
       self.synack = sa
       self.ignored = i

    def show(self):
       print "-------------"
       print "Start : ", self.first_ts
       print "End   : ", self.last_ts   
       print "Duration :" , self.last_ts -self.first_ts
       print "Packets : ", self.packet_count
       print "Packets ignored: ", self.ignored
       print "Bytes : ", self.totalbytes
       print "Throughput : ", self.totalbytes*8/(self.last_ts -self.first_ts)/1024/1024, "Mb/s"
       print "Average packet size : ", self.totalbytes/self.packet_count  
       print "Syn : ", self.synonly
       print "Syn/Ack :", self.synack 
       return






def main(argv=sys.argv):


   packet_count = 0
   packet_count_cur = 0
   start_time = 0
   statistics = []   
   total_bytes = 0
   synonly = 0
   synack = 0
   ignored = 0
 
   f = open(sys.argv[1])     
   pcap = dpkt.pcap.Reader(f)

   for ts, buf in pcap: 
      packet_count += 1
      
      if packet_count == 1:
         start_time =ts

      packet_count_cur += 1
      total_bytes += len(buf)

      eth = dpkt.ethernet.Ethernet(buf)    
      if eth.type!=dpkt.ethernet.ETH_TYPE_IP: 
        ignored += 1
        continue
      
      ip = eth.data
      if ip.p!=dpkt.ip.IP_PROTO_TCP:
        ignored += 1
        continue

      tcp=ip.data
      # print 'TS : ' , ts
      #print 'frame : ' , packet_count
  
     # si le packet est fragemente, la payload n a pas de flag 
      try:
        syn_flag = ( tcp.flags & dpkt.tcp.TH_SYN ) != 0
        ack_flag = ( tcp.flags & dpkt.tcp.TH_ACK ) != 0
        if ( syn_flag and not ack_flag ) :
            synonly += 1
        if (syn_flag and ack_flag ) :
            synack += 1 
      except AttributeError:
            pass
            ignored +=1
            #print 'Passed'

      if  ( (ts - start_time) > 1)  and (packet_count > 1) :

         st = stat( ts_f = start_time, ts_l = ts, pc = packet_count_cur, t = total_bytes, so  = synonly, sa = synack, i = ignored )
         statistics.append(st)
         
         start_time = ts
         synonly = 0
         synack = 0
         packet_count_cur = 0
         total_bytes = 0
         ignored = 0
         continue 

   #Get last second stats
   st = stat( ts_f = start_time, ts_l = ts, pc = packet_count_cur, t = total_bytes,  so  = synonly, sa = synack, i = ignored)
   statistics.append(st)

   '''
   for e in statistics:
      e.show()
   '''
   print "---------------------"
   print "-      SUMMARY      -"
   print "---------------------"
   print "Maximum SYN/ACK :" , max( [ s.synack for s in statistics ] )
   print "Maximum SYN : ", max( [ s.synonly for s in statistics ] )
   print "Maximum PPS : ", max( [ s.packet_count for s in statistics ] )
   print "Maximum Throughput : ", max( [ (s.totalbytes*8/(s.last_ts -s.first_ts)/1024/1024) for s in statistics ] ), "Mb/s"
   
   print "Total packets :" , sum( [ s.packet_count  for s in statistics ] ) 
   return 
 

if __name__ == "__main__":
   main()
 
    
