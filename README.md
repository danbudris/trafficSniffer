# trafficSniffer
A python HTTP traffic sniffer. The traffic sniffer is implemented in the httpSniffer class.  When run as a script, `trafficSniffer.py` will start a reporting thread, then start the traffic sniffer.  The traffic sniffer will grab all HTTP traffic (TCP port 80) on the local network interface, and save it to an in-memory dataframe.  The reporting thread will print out a summary of traffic statistics every 10 seconds.  The report contains the top URL by hits, the top sections of hits to that URL, the sections overall with the greatest number of hits, and a warning as to wether the traffic has exceeded a specific threshold over a predfeined period.  In addition to the warning, once the warning condition is resolved the resolution message will also be displayed.  

## Start the application
From the root directory: `py trafficSniffer.trafficSniffer`

This will start the traffic sniffer, on port 80, and the report thread.  The traffic sniffer will continuously sniff traffic while the report thread will print a traffic report to standardout every 10 seconds.

## Run the Unit Test
From the root directory: `py -m unittest tests.anomalyDetectionTests`

This will run the unit tests for the anaomaly detection methods of the `httpSniffer` class.  

## How we could imporve or extend this
- Seperate the reporting template, currently a HEREDOC in the statuReport method of the httpSniffer class, into its own class, for greater extensibility and customization.

- Adjust scapy to run in a thread in the background, and be able to start/stop it programatically.  Stoping it while running in a thread is tricky, as per numerous github issues.

- Track other packet information about each request, such as dst ip, src ip, DNS server, DNS roundtrip, etc for more interesting details

- Adjust the anomaly detection to factor in the true average traffic over a predefined sample period, as a baseline, and then start alerting on deviations form the sample data, rather than simply alerting on the excess of an arbitrary threshold.   

- Use a library like `curses` to update the status report in-place, rather than re-dump it to stdout each time

- UPdate the anomaly deteciton unit tests to sniff traffic, use `requests` to generate actual http traffic, and then test for the anomalies, rather than generating the very synthentic test data. 

## Author
Dan Budris <d.c.budris@gmail.com>
