from scapy.all import *
from scapy_http import http

import pandas as pd
import numpy as np

from jinja2 import Template

from datetime import datetime
from datetime import timedelta
from time import sleep

import threading
import logging
import curses

class httpSniffer(object):
    """ Sniff HTTP traffic and report on the recorded traffic.
    trafficData is a Pandas dataframe which records the baseUrl, section and path of each sniffed http request.  
    trafficData is indexed by timestamp.

    anaomalyAlarmStatus, anomalyAlarmMessage, anomalyStart, and anomalyEnd are all used to track the status of an ongoing alarm.

    statusReportTpl is a jinja template loaded from a local file, allowing easy editing and swapping of templates.
    
    generateStatusReport
    Renders the status report template with details gathered from the traffic dataframe

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
        # Set up the dataframe for storing traffic information
        self.trafficData = (
            pd.DataFrame(
                columns=['baseUrl', 'section', 'path'],
                index=pd.to_datetime([])
            )
        )

        # Set the alarm status to 'off'
        self.anomalyAlarmStatus = 0
        self.anomalyAlarmMessage = ""
        self.anomalyStart = None
        self.anomalyEnd = None

        # Load the template for the status report from local file
        with open('statusReport.tpl') as templateFile:
            self.statusReportTpl = Template(templateFile.read())

    def generateStatusReport(self):
        ''' Generate the data for the status report, and render it into a template for later display.
        '''
        # Gather the report data from the traffic dataframe                

        reportData = {
            "topSection": (self.trafficData.loc[self.trafficData['section'] == self.trafficData['section'].value_counts().argmax(), ['baseUrl', 'section']]).groupby(['baseUrl','section']).size().head(5).to_string() if not self.trafficData.empty else "None",
            "topHits": self.trafficData.baseUrl.value_counts().head(1).to_string() if not self.trafficData.empty else "None",
            "totalHits": self.trafficData.baseUrl.count(),
            "totalSections": self.trafficData.section.nunique(),
            "totalPaths": self.trafficData.path.nunique(),
            "totalBaseUrls": self.trafficData.baseUrl.nunique(),
            "topPath": self.trafficData.path.value_counts().head(1).to_string() if not self.trafficData.empty else "None",
            "topHitSection": (self.trafficData.loc[self.trafficData['baseUrl'] == self.trafficData['baseUrl'].value_counts().argmax(), ['baseUrl','section']]).groupby(['baseUrl', 'section']).size().head(5).to_string() if not self.trafficData.empty else "None",
            "trafficAverage": round((self.trafficData.baseUrl.count()/self.trafficData.baseUrl.nunique()), 3) if not self.trafficData.empty else "0",
            "anomalyData": self.anomalyAlarmMessage if self.anomalyAlarmMessage != "" else "No Alarms",
            "now": datetime.now().strftime("%I:%M%:%S%p on %B %d, %Y")
        }
        logging.debug(reportData)

        # Load the report data into the template, then return it
        statusReport = self.statusReportTpl.render(reportData)
        
        logging.debug(statusReport)
        return(statusReport)

    def statusReport(self, asDaemon=True, frequency=10):
        ''' Print the status report to stdout, and update in place, and the provided frequency
        '''
        logging.debug("Printing status report")
        stdscr = curses.initscr()
        curses.noecho()
        curses.cbreak()
        
        while True:
            # run the anomaly check
            logging.debug("executing anaomaly check")
            self.anomalyCheck()
            # Display the status report in to Stdout, as an in-place update
            stdscr.clear()
            stdscr.addstr(self.generateStatusReport())
            stdscr.refresh()
            if not asDaemon:
                return()
            sleep(frequency)  

    def anomalyCheck(self, threshold=10, timeRange=2):
        ''' Check if the traffic over the specified time range exceeds the specified threshold.
            If it does, update the alarm attributes and alarm message.
        '''
        # Obtain the number of hits in the specified timerange
        now = datetime.now()
        start =  now - timedelta(minutes=timeRange)
        end = now
        hitsInRange = len(self.trafficData[start:end])
        logging.debug(hitsInRange)
        logging.debug(start, end)
        
        # If the hits exceed the threshold, trigger the alarm
        if hitsInRange >= threshold and self.anomalyAlarmStatus == 0:
            self.anomalyAlarmStatus = 1
            self.anomalyStart = now.strftime("%I:%M%:%S%p on %B %d, %Y")
            self.anomalyAlarmMessage = self.anomalyAlarmMessage + f'\nHigh traffic generated an alert - hits = {hitsInRange}, triggered at {self.anomalyStart}'
            
        # If the alarm continues, note that it continues, and include the hits over the last 2 minutes
        elif hitsInRange >= threshold and self.anomalyAlarmStatus == 1:
            self.anomalyAlarmMessage = self.anomalyAlarmMessage + f'\nHigh traffic continues - hits = {hitsInRange} over {timeRange} minutes'

        # Recover from the alarm, if the hits drop below the threshold and we're in alarm status
        if hitsInRange < threshold and self.anomalyAlarmStatus == 1:
            self.anomalyAlarmStatus = 0
            self.anomalyEnd = now.strftime("%I:%M%:%S%p on %B %d, %Y")
            self.anomalyAlarmMessage = self.anomalyAlarmMessage + f'\nRecovered from excessive traffic alert.  Alert persisted from {self.anomalyStart} to {self.anomalyEnd}'
            
        return

    def sniffTraffic(self, callback=None, packetFilter="tcp port 80"):
        ''' Start the scapy HTTP sniffer, passing packets to the specified callback, and apply the given filter.
        '''
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
