# VirusTotal-Ps

Use the free Virus total API to check different ioc with a single powershell script.
- Hashes
- IP´s
- URL´s
- Domains

In addition, a more detailed .xlsx report will be generated.	

API QUOTA (Free API):
- Request rate:	4 lookups / min
- Daily quota	500: lookups / day
- Monthly quota:	15.5 K lookups / month

NOTE: Due to the limitation of the free API (4 queries per minute) this script performs a delay of 17 seconds in each analysis when there are more than three samples.

1- Add all iocs to the file "resources.txt"

2- Run VirusTotal.ps1 and select the correct option


![menu](https://user-images.githubusercontent.com/88821522/231249145-e2ca4ba7-f033-447b-89ae-62ff8b8dd830.png)

Examples:


![hash](https://user-images.githubusercontent.com/88821522/231249637-28c0265f-01d6-46a0-af1a-649278db9201.png)

![ip](https://user-images.githubusercontent.com/88821522/231249728-f482d11c-869a-48d1-a76d-cfd30c4351ff.png)

![url](https://user-images.githubusercontent.com/88821522/231249825-e252dd3f-3dec-4be5-a5ca-151d6dce9d1c.png)

![domain](https://user-images.githubusercontent.com/88821522/231249866-5e59d42d-566c-47ce-ad31-a0503f2016fb.png)

Example of Domain report:

![domain-report](https://user-images.githubusercontent.com/88821522/231250340-da0f938b-db79-4840-bffe-c9e92d9ade3b.png)


