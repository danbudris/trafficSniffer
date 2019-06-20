# trafficSniffer
A python HTTP traffic sniffer. The traffic sniffer is implemented in the `httpSniffer` class.  When run as a module, `trafficSniffer` will start a reporting thread, then start the traffic sniffer.  The traffic sniffer will grab all HTTP traffic (TCP port 80) on the local network interface, and save it to an in-memory dataframe.  The reporting thread will print out a summary of traffic statistics every 10 seconds.  The report contains the top URL by hits, the top sections of hits to that URL, the sections overall with the greatest number of hits, and a warning as to whether the traffic has exceeded a specific threshold (defaults to 10 hits) over a predefined period (defaults to 2 minutes).  In addition to the alarm, once the alarm condition is resolved the resolution message will also be displayed.  All alarms are retained on-screen.

## PreReqs
Built and tested in a `virtualenv` on OSX.

Requires python 3+

Dependencies are documented in `./requierments.txt`.

To install the dependencies:
`pip install -r ./requierments.txt`

The application must be run as `root` or with `sudo`, to allow access to the network interfaces by [Scapy](https://scapy.net/).

## Start the application
From the project root: `sudo python -m trafficSniffer.trafficSniffer`

This will start the traffic sniffer, on port 80, and the report thread.  The traffic sniffer will continuously sniff traffic while the report thread will display and update-in-place a traffic report to standard out every 10 seconds.

To exit the application, use a keyboard interrupt -- `ctrl + c`.  The `curses` library may cause your terminal to behave strangely, including blank input.  Enter the command `reset` to reset the stdout pipe.

## Run the Unit Tests
From the project root: `sudo python -m unittest tests.anomalyDetectionTests`

This will run the unit tests for the anomaly detection methods of the `httpSniffer` class.  Currently, these four units tests will assert that:
- The alert triggers if there are more than 10 hits in the last 2 minutes
- The alert will not trigger if there are more than 10 hits total, but fewer than 10 in the last 2 minutes
- The alert will not trigger if there are hits in the last 2 minutes, but fewer than 10
- The alert will trigger and then recover if the number of hits in the last 2 minutes drops from more than 10 to less than 10

## How we could improve or extend trafficSniffer
- Use `matplotlib`, `plotly` or some other charting library to generate on-demand historical traffic charts.  Utilizing `pandas` as the data storage and manipulation mechanism opens up a whole world of possibilities for time-series analysis and visualization.

- Add more tests:
  - Test the rate of ingestion that the data frame can handle
  - Test performance of the application as the dataframe grows larger
  - Test the generation of the template
  - Test the individual data extraction functions, to ensure they're pull the right data
 
 - Rather than generating the very synthetic test data, modify the anomaly detection unit tests to sniff traffic, use `requests` to generate actual http traffic, and then test for the anomalies.
 
- Track other packet information about each request, including DNS server, DNS round trip, layer 3 information like dst ip, src ip, and layer 2 information like gateway mac and arp requests etc for more interesting details about traffic and the lan/wan as a whole.  Don't just focus on HTTP, basically, but the whole request lifecycle.  So, build wireshark. :)
  
- Adjust the anomaly detection to factor in the true average traffic over a predefined sample period, as a baseline, and then start alerting on deviations from the sample data, rather than simply alerting on the excess of an arbitrary threshold during a sliding window.
  
- The data extraction with pandas could be optimized/made more clear

- The data extraction with pandas could probably be done elsewhere, outside of the dict that we pass to Jinja, for clarity.  There also may be good places to keep running totals as we process packets, which would allow us to use pre-calculated/cached values rather than extracting them from the dataframe on each run.  This extraction will become unwieldy as the DF grows to any scale.
  
- Flush the data frame after a predefined period of time?  Maybe flush it to disk, to reduce escalating memory consumption.  Perhaps we could use a different data structure other than a `pandas` `dataframe`, like a pcap.

- Adjust `scapy` to run in a thread in the background, and be able to start/stop it programatically.  Stopping it while running in a thread is tricky, as per numerous github issues, and I didn't tackle it here.

- Keep `curses` from breaking the terminal after a keyboard interrupt.

- Track statistical information about the traffic -- hits per second, hits on average over a timeframe, hits on average in the last X minutes per site, etc.  There's a wealth of interesting information that could be added to this program.  I'd be excited to build out more, and really get to know a network and the traffic on it.

- Use `argparse` to add user input to the module, allowing it to be executed with flags which dictate things like the tcp filter and frequency of reporting.  While I'm at it, allow it to read a config file with `configparser`, and derive baseline values from an `.ini`.

- Improve the look of the report template; maybe even build a window with Tkinter, or something, so you have the option of a GUI if you'd like.  That actually seems pretty gratuitous.  

## Author
Dan Budris <d.c.budris@gmail.com>
