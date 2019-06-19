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
        # Rapidly add 11 records to the sniffer dataframe, with a current timestamp
        for i in range(11):
            self.testSniffer.trafficData.loc[pd.Timestamp('now')] == (record)

        # Run the anomaly check
        self.testSniffer.anomalyCheck()

        # Assert that the alert was triggered
        assert(self.testSniffer.anomalyAlarmStatus == 1)

        # Clear the data from the test sniffer dataframe 
        self.testSniffer.iloc[0:0]

    def testAnomalyAlertRecovery(self):
        # Rapidly add 11 records to the sniffer dataframe, with a current timestamp
        for i in range(11):
            self.testSniffer.trafficData.loc[pd.Timestamp('now')] == (record)

        # Run the anomaly check
        self.testSniffer.anomalyCheck()

        # Assert that the sniffer is triggering over the threshold
        assert(self.testSniffer.anomalyAlarmStatus == 1)

        # Clear the packets stored
        self.testSniffer.iloc[0:0]

        # Run the anomaly check -- should set the alarm status back to 0
        self.testSniffer.anomalyCheck()

        # Assert that the alarm status is back to 0, now that we've recovered from the alarm
        assert(self.testSniffer.anomalyAlarmStatus == 0)

        # Clear the data from the test sniffer dataframe    
        self.testSniffer.iloc[0:0]

    def testAnomalyAlertNoTrigger(self):
        # Rapidly add 9 records to the sniffer dataframe, with a current timestamp
        for i in range(9):
            self.testSniffer.trafficData.loc[pd.Timestamp('now')] == (record)

        self.testSniffer.anomalyCheck()

        assert(self.testSniffer.anomalyAlarmStatus == 0)

if __name__ == '__main__':
    unittest.main()
