from scapy.all import *
from scapy_http import http

import pandas as pd
import numpy as np

from datetime import datetime
from datetime import timedelta
from time import sleep

import threading
import logging
import argparse
import curses

class httpSniffer(object):
    """ Sniff HTTP traffic and report on the recorded traffic
    trafficData is a Pandas dataframe which records the baseUrl, section and path of each sniffed http request.  
    trafficData is indexed by timestamp.
    
    generateStatusReport
    Contains the template and data extraction for generating the status report.  Called by the status report daemon.

    statusReport
    Args: 
        asDaemon (bool): run the status report in a loop, for use in a thread
        frequency (int): how often to run the status report, if running as a daemon
        
    anomalyCheck
    Args:
        threshhold (int): the threshhold above which the anomaly alert will trigger
        timerange (int): Look at the last x minutes for anomalies
        
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
        self.anomalyAlarmStatus = 0
        self.anomalyAlarmMessage = ""

    def generateStatusReport(self):
        # Gather the report data
        logging.debug("Generating status report")
        
        topHits = self.trafficData.baseUrl.value_counts().head(1).to_string()
        topHitSection = (self.trafficData.loc[self.trafficData['baseUrl'] == self.trafficData.baseUrl.value_counts().head(1).to_string(index=False), 'section']).head(5).to_string(index=False)
        totalHits = self.trafficData.baseUrl.count()
        totalSections = self.trafficData.section.nunique()
        totalPaths = self.trafficData.path.nunique()
        topPath = self.trafficData.path.value_counts().head(1).to_string()
        topSection = self.trafficData.section.value_counts().head(5).to_string()
        anomalyData = self.anomalyAlarmMessage

        # Generate the report string
        statusReport = f"""
--- Alerts
{anomalyData}
-------------------------
--- Traffic Summary
--- {datetime.now().strftime("%I:%M%:%S%p on %B %d, %Y")}

Top Sections by Hits: \n{topSection}\n

--- General Summary
Total Hits: {totalHits}
Sum of Sections: {totalSections}
Sum of Paths: {totalPaths}
Top Hits by base URL: {topHits}
Top Sections of most popular base URL: \n {topHitSection}
Top Path by Hits: {topPath}
--------------------------
"""
        logging.debug(statusReport)
        return(statusReport)

    def statusReport(self, asDaemon=True, frequency=10):
        logging.debug("Printing status report")
        stdscr = curses.initscr()
        curses.noecho()
        curses.cbreak()
        
        while True:
            try:
                # run the anomaly check
                logging.debug("executing anaomaly check")
                self.anomalyCheck()
                stdscr.clear()
                stdscr.addstr(self.generateStatusReport())
                stdscr.refresh()
                if not asDaemon:
                    return()
                sleep(frequency)
            except KeyboardInterrupt:
                pass    

    def anomalyCheck(self, threshold=10, timeRange=2):
        # Obtain the number of hits in the specified timerange
        now = datetime.now()
        start =  now - timedelta(minutes=timeRange)
        end = now
        hitsInRange = len(self.trafficData[start:end])
        logging.debug(hitsInRange)
        logging.debug(start, end)
        
        # If the hits exceed the threshold, trigger the alarm
        if hitsInRange >= threshold:
            self.anomalyAlarmStatus = 1
            self.anomalyAlarmMessage = self.anomalyAlarmMessage + f'\nWARNING: {hitsInRange} hits over {timeRange} minutes!! Traffic Threshold exceeded!! {now.strftime("%I:%M%:%S%p on %B %d, %Y")}'
            
        # Recover from the alarm, if the hits drop below the threshold and we're in alarm status
        if hitsInRange < threshold and self.anomalyAlarmStatus == 1:
            self.anomalyAlarmStatus = 0
            self.anomalyAlarmMessage = self.anomalyAlarmMessage + f'\nRecovered from excessive traffic {now.strftime("%I:%M%:%S%p on %B %d, %Y")}'
            
        return()

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
        httpLayer = pkt.getlayer(http.HTTPRequest)
        ipLayer = pkt.getlayer(IP)

        # Encode the packet data in UTF-8 from bytes, and processes as needed
        baseUrl = httpLayer.fields["Host"].decode("utf-8")
        section = (httpLayer.fields["Path"].decode("utf-8")).split("/")[1]
        path = httpLayer.fields["Path"].decode("utf-8")

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

    # Start the reporting thread, to run concurrently with the sniffing
    statusReport = traffic.statusReport
    thread1 = threading.Thread(target=statusReport)
    thread1.setDaemon(True)
    thread1.start()

    traffic.sniffTraffic()

if __name__ == "__main__":
    main()
