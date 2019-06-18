# trafficSniffer
A python HTTP traffic sniffer

## Start the application

## Run the Unit Test
py -m unittest tests.anomalyDetectionTests

## How we could imporve or extend this
- Seperate the reporting template, currently a HEREDOC in the statuReport method of the httpSniffer class, into its own class, for greater extensibility and customization.

- Adjust scapy to run in a thread in the background, and be able to start/stop it programatically.  Stoping it 

- Track  other packet information about each request, such as dst ip, src ip, DNS server, DNS roundtrip,etc for more interesting details
- 

## Details
Dan Budris <d.c.budris@gmail.com>