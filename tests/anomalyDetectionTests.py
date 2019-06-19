import unittest
from trafficSniffer.trafficSniffer import httpSniffer
import pandas as pd
import numpy as np
from datetime import datetime
from datetime import timedelta
from time import sleep


class anomalyDetectionTest(unittest.TestCase):
    def setUp(self):
        self.testSniffer = httpSniffer()
        self.record = ['google.com', '/gmail', '/gmail/inbox']

    def testAnomalyAlertTrigger(self):
        # Load 11  records into the sniffer dataframe, with a current timestamp
        for i in range(11):
            self.testSniffer.trafficData.loc[pd.Timestamp('now')] = (self.record)

        # Run the anomaly check
        self.testSniffer.anomalyCheck()

        # Assert that the alert was triggered, due to the number of recent timestamp events exceeding the alert threshold
        assert(self.testSniffer.anomalyAlarmStatus == 1)

    def testAnomalyAlertRecovery(self):
        # Load 11  records into the sniffer dataframe, with a current timestamp
        for i in range(11):
            self.testSniffer.trafficData.loc[pd.Timestamp('now')] = (self.record)

        # Run the anomaly check
        self.testSniffer.anomalyCheck()

        # Assert that the sniffer is triggering over the threshold
        assert(self.testSniffer.anomalyAlarmStatus == 1)

        # Clear the packets stored in the dataframe
        self.testSniffer.trafficData = self.testSniffer.trafficData[0:0]

        # Run the anomaly check again -- should set the alarm status back to 0
        self.testSniffer.anomalyCheck()
        print(self.testSniffer.trafficData)

        # Assert that the alarm status is back to 0, now that we've recovered from the alarm
        assert(self.testSniffer.anomalyAlarmStatus == 0)

    def testAnomalyAlertNoTrigger(self):
        # Rapidly add 9 records to the sniffer dataframe, with a current timestamp
        for i in range(9):
            self.testSniffer.trafficData.loc[pd.Timestamp('now')] = (self.record)

        # Run the anomaly check
        self.testSniffer.anomalyCheck()

        # Assert that the alarm status is 0
        assert(self.testSniffer.anomalyAlarmStatus == 0)

        for i in range(11):
            self.testSniffer.trafficData.loc[pd.Timestamp('now') - pd.Timedelta(minutes=5)] = (self.record)
        
if __name__ == '__main__':
    unittest.main()
