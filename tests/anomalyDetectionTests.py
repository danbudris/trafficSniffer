import unittest
import trafficSniffer.trafficSniffer


class anomalyDetectionTest(unittest.TestCase):
    def setUp(self):
        self.testSniffer = trafficSniffer.httpSniffer()
        self.record = ['google.com', '/gmail', '/gmail/inbox']

    def testAnomalyAlertTrigger():
        # Rapidly add 11 records to the sniffer dataframe, with a current timestamp
        for i in range(11):
            testSniffer.trafficData.loc[pd.Timestamp('now')] == (record)

        # Run the anomaly check
        testSniffer.anomalyCheck()

        # Assert that the alert was triggered
        assert(testSniffer.anomalyAlarmStatus == 1)

        # Clear the data from the test sniffer dataframe 
        testSniffer.iloc[0:0]

    def testAnomalyAlertRecovery():
        # Rapidly add 11 records to the sniffer dataframe, with a current timestamp
        for i in range(11):
            testSniffer.trafficData.loc[pd.Timestamp('now')] == (record)

        # Run the anomaly check
        testSniffer.anomalyCheck()

        # Assert that the sniffer is triggering over the threshold
        assert(testSniffer.anomalyAlarmStatus == 1)

        # Clear the packets stored
        testSniffer.iloc[0:0]

        # Run the anomaly check -- should set the alarm status back to 0
        testSniffer.anomalyCheck()

        # Assert that the alarm status is back to 0, now that we've recovered from the alarm
        assert(testSniffer.anomalyAlarmStatus == 0)

        # Clear the data from the test sniffer dataframe    
        testSniffer.iloc[0:0]

    def testAnomalyAlertNoTrigger():
        # Rapidly add 9 records to the sniffer dataframe, with a current timestamp
        for i in range(9):
            testSniffer.trafficData.loc[pd.Timestamp('now')] == (record)

        testSniffer.anomalyCheck()

        assert(testSniffer.anomalyAlarmStatus == 0)

if __name__ == '__main__':
    unittest.main()