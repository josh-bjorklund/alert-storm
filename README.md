# alert-storm
PowerShell script to clear and resolve an alert storm in the SentinelOne console. 

In the script itself change the console URL and site ID(s) to fit your environment. This can accept one or multiple comma seperated site IDs. 

At run time, provide your API key, and the hash value of the false positive or desired threat to begin resolving threats. 

By default the threat and analyst verdict is false positive, but this can be changed to any value you'd like. 

USAGE: .\alert-storm.ps1  >  Follow prompts


<img width="719" height="190" alt="image (10)" src="https://github.com/user-attachments/assets/04a367b1-5b73-496f-935b-e4f3ed05cc19" />
