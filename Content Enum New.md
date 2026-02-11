## Initial Scans
1. Burp
2. ZAP
3. wafw00f
## Content Enumeration
1. sitemap.xml robots.txt extract (extract)
2. gau.exe (outputs text file)
3. katana - spider (outputs text file)
4. ffuf output json and extract 200s and 403s (extract)
5. nuclei admin pannel
6. google dork (admin panels)
7. extract and concatenate URLs
8. Run eyewitness
9. try 403 bypasses with headers, header values, url appends, and server specific 403 bypasses
10. google dork parameters
## API Enumeration
1. Documentation Discovery
2. kiterunner
3. arjun parameter enumeration
4. google dork paramters
## Fingerprinting 
1. HTTrack and grep commands for HTML comments etc
2. whatweb
3. header inspection (server, cookies)
4. nuclei finger printing
5. Verbose error messages (fuzz entry points with special character lists)
6. google dork common CMS 
7. If no CMS found, ffuf fingerprinting
## Credential Enumeration
1. HTTrack clone
2. katana js crawl
3. trufflehog filesystem on both
## Entry Point Enumeration
 1.   parameter enumeration arjun
 2. parameter enumeration paramspider
 3. Burp param miner
 4. Note down each application entry point
## Vulnerability Enumeration
### Known Exploits
1. Google search for exploits against fingerprinted technologies (server, cms, framework, js libraries).
### Undiscovered Exploits
1. nuclei
2. nikto
3. sqlmap
4. sstimap
5. lfiscanner