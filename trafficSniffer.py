from scapy.all import *
from scapy_http import http

import pandas as pd
import numpy as np

import threading

from datetime import datetime
from time import sleep

import curses
import logging
import argparse


class httpSniffer(object):
    """ Sniff HTTP traffic and report on the recorded traffic
    trafficData is a Pandas dataframe which records the baseUrl, section and path of each sniffed http request.  
    trafficData is indexed by timestamp.
    
    statusReport
    Args: 
        asDaemon (bool): run the status report in a loop, for use in a thread
        frequency (int): how often to run the status report, if running as a daemon
        
    anomalyCheck
    Args:
        threshhold (int): the threshhold above which the anomaly alert will trigger
        timeWindow (int): the window, in minutes, in which to check for anomoalous traffic
        
    sniffTraffic
    Args: 
        callback (func): a callback to be executed on sniffed packets; defaults to the class method processPackets
        packetFilter (string): a scapy packet filter; defaults to TPC and 80
    
    processPackets
    Args:
        pkt (object): a packet sniffed from the network by scapy sniff 
    """
    
    def __init__(self):
        self.trafficData = (
            pd.DataFrame(
                columns=['baseUrl', 'section', 'path'],
                index=pd.to_datetime([])
            )
        )
        self.anomalyAlarm = ""

    def statusReport(self, asDaemon=True, frequency=10):
        while True:
            topHits = self.trafficData.baseUrl.value_counts().head(1).to_string()
            topHitSection = (self.trafficData.loc[self.trafficData['baseUrl'] == self.trafficData.baseUrl.value_counts().head(1).to_string(index=False), 'section']).head(5).to_string(index=False)
            totalHits = self.trafficData.baseUrl.count()
            totalSections = self.trafficData.section.nunique()
            totalPaths = self.trafficData.path.nunique()
            topPath = self.trafficData.path.value_counts().head(1).to_string()
            topSection = self.trafficData.section.value_counts().head(1).to_string()

            statusReport = f"""
{self.anomalyAlarm}
-------------------------
--- Traffic Summary
--- {datetime.now().strftime("%I:%M%:%S%p on %B %d, %Y")}
--- Most Accessed URL

Top Hits by base URL: {topHits}
Top Sections: \n {topHitSection}

--- General Summary
Total Hits: {totalHits}

Total Sections: {totalSections}
Top Section Overall: {topSection}

Total Paths: {totalPaths}
Top Path Overall: {topPath}
--------------------------
"""

            print(statusReport)
            if not asDaemon:
                return()
            sleep(frequency)

    def anomalyCheck(self, threshold=10, asDaemon=True, frequency=120):
        report = "TESTING ANOMALY REPORT"
        if asDaemon:
            while True:
                print(report)
                sleep(frequency)
        else:
            return(report)

    def sniffTraffic(self, callback=None, packetFilter="tcp port 80"):
        # if there's no custom callback set, use the default class method
        if not callback:
            callback = self.processPackets

        logging.info("Starting packet capture...")
        sniff(prn=callback, filter=packetFilter)

    def processPackets(self, pkt):
        # Don't process non-http traffic
        if not pkt.haslayer(http.HTTPRequest):
            return

        # Parse out the HTTP layer of the traffic
        http_layer = pkt.getlayer(http.HTTPRequest)
        ip_layer = pkt.getlayer(IP)

        # Encode the packet data in UTF-8 from bytes, and processes as needed
        baseUrl = http_layer.fields["Host"].decode("utf-8")
        section = (http_layer.fields["Path"].decode("utf-8")).split("/")[1]
        path = http_layer.fields["Path"].decode("utf-8")

        # Add the packet information to the overall traffic dataframe
        self.trafficData.loc[pd.Timestamp('now')] = ([baseUrl, section, path])
        #print(self.trafficData)
        return


def main():
    '''
        Main function for executing the reporting concurrently with the traffic sniffing
    '''
    # Initialize the base traffic tracker
    traffic = httpSniffer()

    # Start the reporting threads, to run concurrently with the sniffing
    statusReport = traffic.statusReport
    anomalyReport = traffic.anomalyCheck
    thread1 = threading.Thread(target=statusReport)
    thread2 = threading.Thread(target=anomalyReport)
    thread1.setDaemon(True)
    thread2.setDaemon(True)
    thread1.start()
    thread2.start()

    traffic.sniffTraffic()

if __name__ == "__main__":
    main()
