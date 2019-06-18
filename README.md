# trafficSniffer
A python HTTP traffic sniffer.  When run as a script, this program will start a reporting thread, then start the traffic sniffer.  The traffic sniffer will grab all HTTP traffic (TCP port 80) on the local, and save it to an in-memory dataframe.  The reporting thread will print out a summary of traffic statistics every 10 seconds, incluidng an anomaly report which alerts on traffic over the last two minutes exceeding a threshold.

## Start the application

## Run the Unit Test
From the root directory: `py -m unittest tests.anomalyDetectionTests`

## How we could imporve or extend this
- Seperate the reporting template, currently a HEREDOC in the statuReport method of the httpSniffer class, into its own class, for greater extensibility and customization.

- Adjust scapy to run in a thread in the background, and be able to start/stop it programatically.  Stoping it 

- Track  other packet information about each request, such as dst ip, src ip, DNS server, DNS roundtrip,etc for more interesting details

- Adjust the anomaly detection to factor in the true average traffic over a predefined sample period, as a baseline, and then start alerting on deviations form the sample data, rather than simply alerting on the excess of an arbitrary threshold.   

## Details
Dan Budris <d.c.budris@gmail.com>
