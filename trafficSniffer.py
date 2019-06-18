import pandas as pd
import numpy as np

import threading

from datetime import datetime
from time import sleep

import logging
import argparse


class httpSniffer(object):
    def __init__(self):
        self.trafficData = (
            pd.DataFrame(
                columns=['baseUrl', 'section', 'path'],
                index=pd.to_datetime([])
            )
        )

    def statusReport(self, asDaemon=True, frequency=10):
        # run some logic to get the highest count among base URLs,
        # incldue the 'sections' and their count for that base URL,
        # include the total number of hits, 
        # include the top 5 number of hits over the last minute?
        report = "TESTING STATUS REPORT"
        if asDaemon:
            while True:
                print(report)
                sleep(frequency)
        else:
            return(report)

    def anomalyCheck(self, threshold=10, asDaemon=True, frequency=120):
        # get all elements in hitsOverTime which occured in the last 2 minutes
        # if this value is greater than the threshold, add an alert which will be constantly printed with the every-10-seconds alerting
        # slice the trafficDatda dataframe to get a count of all events newer than 2 minutes
        # if that count is greater than the threshold value trigger the alert
        report = "TESTING ANOMALY REPORT"
        if asDaemon:
            while True:
                print(report)
                sleep(frequency)
        else:
            return(report)

    def sniffTraffic(self, callback=None, packetFilter="tcp port 80"):
        if not callback:
            callback = self.processPackets

        logging.info("Starting packet capture...")
        sniff(prn=callback, filter=packetFilter)

    def processPackets(self, pkt):
        
        # Don't process non-http traffic
        if not pkt.haslayer(http.HTTPRequest):
            return

        # Parse out the HTTP layer of the traffic
        http_layer = packet.getlayer(http.HTTPRequest)
        ip_layer = packet.getlayer(IP)

        # Encode the packet data in UTF-8 from bytes, and processes as needed
        baseUrl = http_layer.fields[Host].encode("utf-8")
        section = (http_layer.fields[Path].encode("utf-8")).split("/")[1]
        path = http_layer.fields[Path].encode("utf-8")

        # Add the packet information to the overall traffic dataframe
        self.trafficData.loc[pd.TimeStamp('now')] = ([baseUrl, section, path])
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

    while True:
        # Do the scapy sniff
        print("testing")
        sleep(6)

if __name__ == "__main__":
    sniffer = httpSniffer()
    sniffer.trafficData.loc[pd.Timestamp('now')] = (['1', '2', '3'])
    print(sniffer.trafficData)

    main()
    # notes
    # get value counts
    # https://stackoverflow.com/questions/29626543/filter-select-rows-of-pandas-dataframe-by-timestamp-column
    # https://stackoverflow.com/questions/49868647/how-to-slice-a-pandas-dataframe-based-on-datetime-index
    # https://cmdlinetips.com/2018/02/how-to-get-frequency-counts-of-a-column-in-pandas-dataframe/
