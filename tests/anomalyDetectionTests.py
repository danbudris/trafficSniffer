import unittest
from trafficSniffer.trafficSniffer import httpSniffer
import pandas as pd


class anomalyDetectionTest(unittest.TestCase):
    def setUp(self):
        # Set up th base class to use, and a simple record to use in the tests
        self.testSniffer = httpSniffer()
        self.record = ['google.com', '/gmail', '/gmail/inbox']

    def testAnomalyAlertTrigger(self):
        # Ensure the dataframe is clear
        self.testSniffer.trafficData = self.testSniffer.trafficData[0:0]
        
        # Load 15  records into the sniffer dataframe, with a current timestamp
        for i in range(15):
            self.testSniffer.trafficData.loc[pd.Timestamp('now')] = (self.record)

        # Run the anomaly check
        self.testSniffer.anomalyCheck()

        # Assert that the alert was triggered, due to the number of recent timestamp events exceeding the alert threshold
        assert(self.testSniffer.anomalyAlarmStatus == 1)

    def testAnomalyAlertRecovery(self):
        # Ensure the dataframe is clear
        self.testSniffer.trafficData = self.testSniffer.trafficData[0:0]
        
        # Load 15  records into the sniffer dataframe, with a current timestamp
        for i in range(15):
            self.testSniffer.trafficData.loc[pd.Timestamp('now')] = (self.record)

        # Run the anomaly check
        self.testSniffer.anomalyCheck()

        # Assert that the alert is triggering over the threshold
        assert(self.testSniffer.anomalyAlarmStatus == 1)

        # Clear the packets stored in the dataframe
        self.testSniffer.trafficData = self.testSniffer.trafficData[0:0]

        # Run the anomaly check again -- should set the alarm status back to 0
        self.testSniffer.anomalyCheck()

        # Assert that the alarm status is back to 0, now that we've recovered from the alarm
        assert(self.testSniffer.anomalyAlarmStatus == 0)

    def testAnomalyAlertNoTriggerLowThreshold(self):
        # Ensure the dataframe is clear
        self.testSniffer.trafficData = self.testSniffer.trafficData[0:0]
        
        # Rapidly add 9 records to the sniffer dataframe, with a current timestamp
        for i in range(9):
            self.testSniffer.trafficData.loc[pd.Timestamp('now')] = (self.record)

        # Run the anomaly check
        self.testSniffer.anomalyCheck()

        # Assert that the alarm status is 0, as 9 is below the threshold of 10
        assert(self.testSniffer.anomalyAlarmStatus == 0)

    def testAnomalyAlertNoTriggerTimeFrame(self):
        # Ensure the dataframe is clear
        self.testSniffer.trafficData = self.testSniffer.trafficData[0:0]
        
        # Add 11 records to the sniffer dataframe, with a timestamp outside of the 2 minute window
        for i in range(20):
            self.testSniffer.trafficData.loc[pd.Timestamp(2017, 1, 1, 12)] = (self.record)

        # Run the anomaly check
        self.testSniffer.anomalyCheck()

        # Asser that the alarm is not triggering, due to the events being outside the 2 minute window
        assert(self.testSniffer.anomalyAlarmStatus == 0)
        
if __name__ == '__main__':
    unittest.main()

