# TA-DUOSecurity2FA
Splunk TA for indexing DUO 2 factor activity logs

Prerequisites:
DUO Security (https://duo.com/) admin account that has read access
to DUO Admin API.
You'll need the DUO API host, an Integration Key and Secret Key.

Deployment options:
For a single instance Splunk system, install by the usual installation method. 

For distributed Splunk systems, the recommended place to install would be
on a heavy forwarder, but could also be setup on a search head as long as
the search head is configured to forward data to you indexing tier.

Configuration steps:
Once installed, a local input type titled "DUO Security 2fa logs" should be
listed under Data inputs.
-Select the "DUO Security 2fa logs" input. 
-Click the "New" button at the top.  
-Enter unique descriptive name for the input
-Enter relavant API host and credential information
-Set the number of days of historical data you'd like to pull the first time
  After the first run of the input, this setting won't have any affect
  as the checkpointing process maintains the time of the last indexed event.
-Set the interval in seconds at which datai is pulled, if it is set too low
  Duo will return a 429 "too many requests" error so you may want to monitor
  you're splunkd.log for this error message.
-Select which DUO logs you want to enable
-Click "Next"
-If the API hostname and credentials verify correctly, the input setup
  should complete successfully.

Optional configurations:
-Clicking "More settings" radio button, allows you to select a different
 index than the default

Another option would be to configure a separate input for each log type,
if you want to specify a different interval or index for each one. e.g.
an interval of 120 sec for authentication logs, going to an auth index
and an interval of 600 seconds for administrator logs, going to an admin
index.
