# trafficSniffer
A python HTTP traffic sniffer. The traffic sniffer is implemented in the httpSniffer class.  When run as a script, `trafficSniffer.py` will start a reporting thread, then start the traffic sniffer.  The traffic sniffer will grab all HTTP traffic (TCP port 80) on the local network interface, and save it to an in-memory dataframe.  The reporting thread will print out a summary of traffic statistics every 10 seconds.  The report contains the top URL by hits, the top sections of hits to that URL, the sections overall with the greatest number of hits, and a warning as to wether the traffic has exceeded a specific threshold over a predfeined period.  In addition to the warning, once the warning condition is resolved the resolution message will also be displayed.  

## PreReqs
Built and tested on OSX.

Requires python 3+

Requierments are codified in `./requierments.txt`.

To install the reqs:
`pip3 install -r ./requierments.txt`

The application and tests must be run as `root` or with `sudo`, to allow access to the network interfaces by Scapy.

## Start the application
From the project root: `sudo python -m trafficSniffer.trafficSniffer`

This will start the traffic sniffer, on port 80, and the report thread.  The traffic sniffer will continuously sniff traffic while the report thread will display and update-in-place a traffic report to standardout every 10 seconds.

## Run the Unit Test
From the project root: `sudo python -m unittest tests.anomalyDetectionTests`

This will run the unit tests for the anaomaly detection methods of the `httpSniffer` class.  

## How we could imporve or extend this
- Seperate the reporting template, currently a HEREDOC in the statuReport method of the httpSniffer class, into its own class + template, and use a templating engine like `jinja2` in order to generate the final report.  

- Use `matplotlib`, `plotly` or some other charting library to generate on-demand histroical traffic charts.  Utilizing `pandas` as the data storage and manipulation mechanims opens up a whole world of possibilities for time-series analysis and visualzation.

- Add more tests:
  - Test the rate of ingestion that the dataframe can handle
  - Test performance of the application as the dataframe grows larger
  - Test the generation of the template
  - Test the individual data extraction functions, to ensure they're pull the right data
  
- Flush the dataframe after a predefined period of time?  Maybe flush it to disk, to reduce escalating memory consumption.  Perhaps we could use a different data structure other than a df, like pcap, too.

- Adjust scapy to run in a thread in the background, and be able to start/stop it programatically.  Stoping it while running in a thread is tricky, as per numerous github issues, and I didn't tackle it here.

- Track other packet information about each request, including DNS server, DNS roundtrip, layer 3 information like dst ip, src ip, and layer 2 information like gateway mac and arp requests etc for more interesting details about traffic and the lan/wan as a whole.

- Adjust the anomaly detection to factor in the true average traffic over a predefined sample period, as a baseline, and then start alerting on deviations form the sample data, rather than simply alerting on the excess of an arbitrary threshold.   

- Rather than generating the very synthentic test data, modify the anomaly deteciton unit tests to sniff traffic, use `requests` to generate actual http traffic, and then test for the anomalies.

## Author
Dan Budris <d.c.budris@gmail.com>
