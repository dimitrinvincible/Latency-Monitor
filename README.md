# Latency-Monitor
diagnostic python script to view computer information during latency spikes


The purpose of this program is to help isolate, and potentially identify, what is happening
during latency spikes on your computer.

Currently the python program will run continuously pinging designated IP until latency spikes above 100
and then it will look at your GPU, CPU and RAM Usage, while also performing deep packet inspection during the latency.

It will not doing these things continously, only while latency is above the threshold you set and while
a specific application that you set is running.

Steps to Use:

1. download python program
2. set your needed variables for TARGET (destination IP to send pings to. default is google DNS)
   LATENCY_THRESHOLD_MS (latency in ms that you want it to trigger the capture)
   PING_INTERVAL is how many seconds between each ping attempt, default is 3
   and PROCESS_TO_MONITOR is where you define the application you want it to look for.
3. run the program


It will not start pinging until it detects the running application, and it will not log data or perform packet analysis
unless latency spikes while the specific application is open.

Current Version: 1.0 
tested and used at home to identify further some issues I have been having while playing Ready Or Not
and figured it could be a useful tool for anyone else, especially anyone who is not sure how or where to start
to review information. Or simply gets overwhelmed looking at all the TCPview, wireshark, sysmon, and resource/task manager windows.

Cheers
