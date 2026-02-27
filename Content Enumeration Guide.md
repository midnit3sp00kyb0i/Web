
# Initial Scans
1. Burp
2. ZAP
3. wafw00f
4. nikto
5. nuclei
6. While the scans run have a poke around and try and find - natural differing response codes, obtain cookies

# Server Configuration Analysis
Nuclei configuration:
```
nuclei https://target.xyz -tags config,ssl
```
Finding server version with `nuclei`:
```
katana -u https://target.xyz | head -n 30 | nuclei -t detect-web-servers
```
Finding server version with `nmap`:
```
nmap target.xyz -p 443 -sC -sV -A -p 443 -oN serverversion.nmap
```
Testssl:
```
testssl https://target.xyz
```
# HTTP Response Analysis
Run nuclei scans for fingerprinting:
```
nuclei -u https://target.xyz -as
nuclei -u https://target.xyz -tags generic,tech-detect
```
Basic commands:
```
whatweb https://target.xyz
```
Request different HTTP versions:
```
curl --http0.9 https://target.xyz
curl --http1.0 https://target.xyz
curl --http1.1 https://target.xyz
curl --http2 https://target.xyz
curl --http2-prior-knowledge https://target.xyz
curl --http3 https://target.xyz
```
Request with different HTTP methods:
```
ffuf -u 'https://target.xyz' -X FUZZ -w fuzzing/http-request-methods.txt
```
Request to provoke differing response codes:
```
curl http://target.xyz/%
curl http://target.xyz/% -I
curl http://target.xyz/non/existant/path
curl http://target.xyz/non/existant/path -I
```
Cookie inspection:
```
curl https://target.xyz -I
```

| Framework         | Cookie name                       |
| ----------------- | --------------------------------- |
| Zope              | zope3                             |
| CakePHP           | cakephp                           |
| Kohana            | kohanasession                     |
| Laravel           | laravel_session                   |
| phpBB             | phpbb3_                           |
| WordPress         | wp-settings                       |
| 1C-Bitrix         | BITRIX_                           |
| AMPcms            | AMP                               |
| Django CMS        | django                            |
| DotNetNuke        | DotNetNukeAnonymous               |
| e107              | e107_tz                           |
| EPiServer         | EPiTrace, EPiServer               |
| Graffiti CMS      | graffitibot                       |
| Hotaru CMS        | hotaru_mobile                     |
| ImpressCMS        | ICMSession                        |
| Indico            | MAKACSESSION                      |
| InstantCMS        | InstantCMS[logdate]               |
| Kentico CMS       | CMSPreferredCulture               |
| MODx              | SN4[12symb]                       |
| TYPO3             | fe_typo_user                      |
| Dynamicweb        | Dynamicweb                        |
| LEPTON            | lep[some_numeric_value]+sessionid |
| Wix               | Domain=.wix.com                   |
| VIVVO             | VivvoSessionId                    |
| Tiny File Manager | filemanager                       |
| Zenphoto          | zenphoto_auth                     |
JWT Inspection:
Decode the payload of the JWT (the middle payload between the dots):
```
base64 -d <JWT_Payload>
```
# HTML Inspection
Google dork for interesting strings:
```
site:target.xyz "Powered by"
site:target.xyz "Stack trace"
site:target.xyz "Exception"
site:target.xyz "Error at"
```
Clone the site locally:
```
httrack https://target.xyz -O ./local-clone --mirror
```
Run this from `local-clone/..`:
```
grep -RinE '<meta[^>]+name=["'"'"']generator["'"'"']|<body[^>]+id=["'"'"']phpbb["'"'"']|DNN Platform' ./local-clone/
```

| Application | Keyword                                                                        |
| ----------- | ------------------------------------------------------------------------------ |
| WordPress   | `<meta name="generator" content="WordPress 3.9.2" />`                          |
| phpBB       | `<body id="phpbb"`                                                             |
| Mediawiki   | `<meta name="generator" content="MediaWiki 1.21.9" />`                         |
| Joomla      | `<meta name="generator" content="Joomla! - Open Source Content Management" />` |
| Drupal      | `<meta name="Generator" content="Drupal 7 (https://drupal.org)" />`            |
| DotNetNuke  | `DNN Platform - [https://www.dnnsoftware.com](https://www.dnnsoftware.com)`    |
Run this from `local-clone/..`:
```
grep -RinE '<!-- START headerTags\.cfm|__VIEWSTATE|<!-- ZK|<!-- BC_OBNW -->|ndxz-studio' ./local-clone/
```
Run this from `local-clone/..`:
```
grep -RinE '<!--'
```
Run this rom `local-clone/..`:
```
grep -Rnw 
```
Run this from `local-clone/..` to extract all script tags:
```
grep -RohE '<script[^>]+src=["'"'"'][^"'"'"']+' ./local-clone/ | sed -E 's/.*src=["'"'"']([^"'"'"']+)/\1/' | sort -u

```
Extract JS and CSS asset paths  from all pages to extract all script tags `local-clone/..`:
```
grep -RohE '(src|href)=["'"'"'][^"'"'"']+\.(js|css)' ./local-clone/ | sed -E 's/.*(src|href)=["'"'"']([^"'"'"']+)/\2/' | sort -u
```
Extra checks to be ran from `local-clone/..`:
```
grep -RinE 'jquery|wordpress|drupal|joomla|bootstrap|react|vue|angular|webpack' ./local-clone/
```
Use OWASP dependency check on `local-clone/`:
```
dependancy-check --scan ./local-clone
```
Run trufflehog:
```
trufflehog filesystem ./local-clone
```

| Framework         | Keyword                     |
| ----------------- | --------------------------- |
| Adobe ColdFusion  | `<!-- START headerTags.cfm` |
| Microsoft ASP.NET | `__VIEWSTATE`               |
| ZK                | `<!-- ZK`                   |
| Business Catalyst | `<!-- BC_OBNW -->`          |
| Indexhibit        | `ndxz-studio`               |
# JavaScript Inspection
Pull all JS:
```
mkdir jsurls
katana -u https://target.xyz -jc -o jsurls/urls.txt
```
Google dork for JS and add to `jsurls/urls.txt`:
```
site:target.xyz ext:js
site:target.xyz inurl:js
```
Grab all the files locally:
```
while read -r u; do curl -s "$u" > "jsurls/$(echo $u | tr -dc '[:alnum:]').js"; done < jsurls/urls.txt
```
Move `urls.txt` from  `jsurls`:
```
mv jsurls/urls.txt ./
```
Pull paths like API paths from fles:
```
grep -RE ""[^'\"\` ]+\/[^'\"\` ]+"" ./jsurls
```
Run trufflehog:
```
trufflehog filesystem jsurls/urls.txt
```
Also google dork for credentials:
```
site:target.xyz ext:txt inurl:password OR inurl:credentials
site:target.xyz inurl:password OR inurl:credentials -inurl:readme.txt
site:target.xyz intext:user OR intext:pass  
```
Try to find the server side language with google dork:
```
site:target.xyz ext:php
```
Try to find server side language with `ffuf`:
```
ffuf -u https://target.xyz/index.FUZZ -w content/general/raft-large-extensions.txt
```
Try to find server side language with `nuclei`:
```
katana -u https://target.xyz | head -n 30 | nuclei -tags tech
```
# Web Page Enumeration
Extract `sitemap.xml`:
```
SitemapExtract https://target.xyz > sitemapextract.out.txt
```
Grab URLs from AlienVault:
```
gau https://target.xyz > gau.out.txt
```
Spider with `katana`:
```
katana -u https://target.xyz -o katana.out.txt
```
Google dork for admin panels:
```
inurl:admin
inurl:panel
inurl:login
inurl:staff
site:target.xyz inurl:login ext:php -inurl:assets intext:"username" AND intext:"password"
```
Google dork for environment files:
```
site:target.xyz filetype:env intext:password
```
Google dork for backup files:
```
site:target.xyz (ext:bak OR ext:old OR ext:orig OR ext:original OR ext:backup OR ext:backups OR ext:bkup OR ext:bck OR ext:save OR ext:sav OR ext:tmp OR ext:temp OR ext:cache OR ext:copy OR ext:duplicate OR ext:disabled OR ext:example OR ext:sample OR ext:test OR ext:staging OR ext:dev OR ext:development OR ext:local OR ext:sql OR ext:sql.gz OR ext:sql.zip OR ext:sql.tar OR ext:sql.bz2 OR ext:sql.7z OR ext:dump OR ext:dmp OR ext:db OR ext:db2 OR ext:db3 OR ext:sqlite OR ext:sqlite3 OR ext:sqlite-db OR ext:mdb OR ext:accdb OR ext:frm OR ext:ibd OR ext:myd OR ext:myi OR ext:mdf OR ext:ldf OR ext:ndf OR ext:psql OR ext:pgsql OR ext:mysql OR ext:isql OR ext:log OR ext:log1 OR ext:log2 OR ext:log.old OR ext:log.bak OR ext:logfile OR ext:error OR ext:error-log OR ext:err OR ext:out OR ext:stdout OR ext:stderr OR ext:trace OR ext:zip OR ext:rar OR ext:7z OR ext:tar OR ext:tar.gz OR ext:tgz OR ext:tar.bz2 OR ext:gz OR ext:bz2 OR ext:xz OR ext:lz OR ext:lzma OR ext:iso OR ext:env OR ext:env.old OR ext:env.bak OR ext:env.local OR ext:env.dev OR ext:ini OR ext:ini.bak OR ext:cfg OR ext:conf OR ext:config OR ext:cnf OR ext:properties OR ext:yaml OR ext:yml OR ext:toml OR ext:json OR ext:xml OR ext:txt OR ext:txt.old OR ext:txt.bak OR ext:info OR ext:readme OR ext:md OR ext:markdown OR ext:rtf OR ext:html.old OR ext:html.bak OR ext:html.orig OR ext:html.save OR ext:html.tmp OR ext:html.new OR ext:new.html OR ext:html.1 OR ext:html.2 OR ext:htm.old OR ext:htm.bak OR ext:index.html.bak OR ext:default.html.old OR ext:php3 OR ext:php4 OR ext:php5 OR ext:php.old OR ext:php.bak OR ext:php.orig OR ext:php.save OR ext:php.tmp OR ext:php.new OR ext:new.php OR ext:php.1 OR ext:php~ OR ext:php.swp OR ext:php.disabled OR ext:jsp.old OR ext:jsp.bak OR ext:jsp.orig OR ext:jsp.new OR ext:new.jsp OR ext:jsp.1 OR ext:asp.old OR ext:asp.bak OR ext:aspx.old OR ext:aspx.bak OR ext:new.asp OR ext:java OR ext:class OR ext:jar OR ext:war OR ext:ear OR ext:java.old OR ext:jar.old OR ext:war.bak OR ext:py OR ext:pyc OR ext:pyo OR ext:pyd OR ext:py.old OR ext:py.bak OR ext:py.save OR ext:__pycache__ OR ext:venv OR ext:js OR ext:jsx OR ext:mjs OR ext:cjs OR ext:ts OR ext:tsx OR ext:js.old OR ext:js.bak OR ext:js.map OR ext:package-lock.json OR ext:yarn.lock OR ext:rb OR ext:rake OR ext:gem OR ext:rb.old OR ext:rb.bak OR ext:pl OR ext:pm OR ext:cgi OR ext:pl.old OR ext:cgi.bak OR ext:sh OR ext:bash OR ext:zsh OR ext:ksh OR ext:csh OR ext:sh.old OR ext:sh.bak OR ext:bash_history OR ext:c OR ext:cpp OR ext:cc OR ext:cxx OR ext:h OR ext:hpp OR ext:obj OR ext:o OR ext:so OR ext:dll OR ext:exe OR ext:out.old OR ext:git OR ext:gitignore OR ext:gitmodules OR ext:svn OR ext:hg OR ext:bzr OR ext:DS_Store OR ext:swp OR ext:swo OR ext:idea OR ext:vscode OR ext:project OR ext:settings OR ext:iml OR ext:wp-config.php.bak OR ext:configuration.php.old OR ext:settings.php.bak OR ext:localsettings.php.old OR ext:back OR ext:bak1 OR ext:bak2 OR ext:000 OR ext:001 OR ext:002 OR ext:~ OR ext:~~ OR ext:.~)
```


> [!NOTE] Important!
> Please for the love of Christ throttle / rate limit.

### General Dirbust

```
ffuf -u 'https://target.xyz/FUZZ' -w content/general/quick_hits.txt -o quickhits.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/general/common_directories.txt -o common_directories.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/general/common.txt -o common.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/general/common2.txt -o common.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/general/dir.txt -o dir.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/general/fuzz.txt -o fuzz.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/general/god.txt -o god.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/general/all.txt -o all.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/general/1.txt -o 1.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/general/all_dirs.txt -o all_dirs.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/general/raft_large_directories.txt -o raft_large_directories.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/general/raft_large_files.txt -o raft_large_files.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/general/big.txt -o big.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/general/DirBuster-2007_directory-list-2.3-big.txt -o DirBuster-2007_directory-list-2.3-big.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ1.FUZZ2' -w FUZZ1:content/general/raft_large_files.txt -w FUZZ1:content/general/raft_large_extensions.txt -o raft_words_extensions.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ1.FUZZ2' -w FUZZ1:content/general/all_dirs.txt -w FUZZ1:content/general/raft_large_extensions.txt -o all_dirs_ext.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ1.FUZZ2' -w FUZZ1:content/general/combined_words.txt -w FUZZ1:content/general/combined_words.txt -o combined_words_extensions.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ1.FUZZ2' -w FUZZ1:content/general/combined_directories.txt -w FUZZ1:content/general/combined_words.txt -o combined_directories_extensions.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ1.FUZZ2' -w FUZZ1:content/general/big.txt -w FUZZ1:content/general/combined_words.txt -o big_ext.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ1.FUZZ2' -w FUZZ1:content/general/DirBuster-2007_directory-list-2.3-big.txt -w FUZZ1:content/general/raft_large_extensions.txt -o dirbuster_with_extensions.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/general/generic_app_server.txt -o generic_app_server.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/general/top-10000.txt -o top-10000.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/general/vulnerability-scan_j2ee-websites_WEB-INF.txt -o vulnerability-scan_j2ee-websites_WEB-INF.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/general/tftp.fuzz.txt -o tftp.fuzz.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/general/wso2-enterprise-integrator.txt -o wso2-enterprise-integrator.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/general/dsstorewordlist.txt -o dsstorewordlist.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/general/WordlistSkipfish.txt -o WordlistSkipfish.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/general/password_file_locations.txt -o password_file_locations.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/general/cgi-bin.txt -o cgi-bin.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/general/jsf.txt -o jsf.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/general/KitchensinkDirectories.txt -o KitchensinkDirectories.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/general/wellknown-rfc5785.txt -o wellknown-rfc5785.fuzzout.json
```

### Login Panels

```
ffuf -u 'https://target.xyz/FUZZ' -w content/general/html_logins.txt -o html_logins.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/general/Logins.fuzz.txt -o Logins.fuzz.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ content/general/admin_panels.txt -o admin_panels.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/general/AdminPanelsCustom.txt -o AdminPanelsCustom.txt.fuzzout.json
```

### Upload Locations

```
ffuf -u 'https://target.xyz/FUZZ' -w content/general/upload_variants.txt -o upload_variants.fuzzout.json
```

### Config Files

```
ffuf -u 'https://target.xyz/FUZZ' -w content/general/Proxy-Auto-Configuration-Files.txt -o Proxy-Auto-Configuration-Files.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/general/Metafiles.txt -o Metafiles.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/general/versioning_metafiles.txt -o versioning_metafiles.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/general/UnixDotFiles.txt -o UnixDotFiles.fuzzout.json
```

### Backups

```
ffuf -u 'https://target.xyz/FUZZ' -w content/general/Common-DB-Backups.txt -o Common-DB-Backups.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ1FUZZ2' -w FUZZ1:content/general/copy_of.txt -w FUZZ2:<wordlist_of_known_inaccessible_files>

ffuf -u 'https://target.xyz/FUZZ' -w content/general/backup_files_only.txt -o backup_files_only.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/general/Randomfiles.txt -o Randomfiles.fuzzout.json
```

### App Server Specific

```
ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/ActiveDirectory-small.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/ADFS.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/AdobeXML.fuzz.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/AdobeXML.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/Apache-Axis.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/Apache-Tomcat.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/Apache.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/ApacheTomcat.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/Apache_Axis.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/Apache_other.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/ColdFusion.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/coldfusion_other.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/confluence-administration.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/domino-dirs-coldfusion39.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/domino-endpoints-coldfusion39.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/Domino-Files.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/FatwireCMS.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/Frontpage.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/Glassfish-Sun-Microsystems.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/hashicorp-consul-api.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/hashicorp-vault.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/HP-System-Management-Homepage.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/HP_System_Mgmt_Homepage.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/HTTP_POST_Microsoft.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/Hyperion.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/IBM-WebSphere-Application-Server.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/IIS-POST.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/IIS-systemweb.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/IIS.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/IIS_other.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/Java-Servlet-Runner-Adobe-JRun.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/JavaServlets-Common.fuzz.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/JavaServlets_Common.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/JBoss.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/JBoss_other.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/Jenkins-Hudson.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/Joomla_exploitable.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/JRun.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/Keycloak-Identity-Access-Management.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/LotusNotes.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/Microsoft-Forefront-Identity-Manager.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/Microsoft-Frontpage.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/Netware.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/netware_other.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/nginx.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/openwrt-luci-enpoints.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/Oracle-Sun-iPlanet.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/Oracle-WebLogic.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/Oracle9i.fuzz.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/Oracle9i.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/OracleAppServer.fuzz.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/OracleAppServer.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/PulseSecure-VPN.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/Roundcube-123.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/rssfeed-files.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/rstp.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/Ruby_Rails.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/sap-analytics-cloud.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/SAP-NetWeaver.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/SAP.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/Sharepoint.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/SiteMinder.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/SuniPlanet.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/Swagger.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/Weblogic.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/Websphere.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/server_specific/kibana.txt'
```

### CMS Specific

```
ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/Adobe-AEM_2021.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/AdobeCQ-AEM_2017.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/aimeos-all-levels.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/aimeos.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/bagisto-all-levels.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/bagisto.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/bluedit.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/bolt-all-levels.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/bolt.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/caobox-cms.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/cms-configuration-files.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/ColdFusion.fuzz.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/craftcms-all-levels.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/craftcms.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/crater-all-levels.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/crater.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/directus-all-levels.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/directus.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/django-cms-all-levels.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/django-cms.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/Django.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/dolibarr-all-levels.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/dolibarr.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/dotnetnuke.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/drupal-all-levels.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/drupal-themes.fuzz.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/drupal_plugins.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/Drupal.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/drupal1.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/erpnext-all-levels.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/erpnext.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/espocrm-all-levels.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/espocrm.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/fatfreecrm-all-levels.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/fatfreecrm.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/flarum-all-levels.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/flarum.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/flyspray-1.0RC4.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/forkcms-all-levels.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/forkcms.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/ghost-all-levels.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/ghost.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/grav-all-levels.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/grav.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/joomla-all-levels.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/joomla-plugins.fuzz.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/joomla-themes.fuzz.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/joomla.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/kentico-cms-modules-themes.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/keystonejs-all-levels.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/keystonejs.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/laravel-all-levels.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/laravel.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/liferay_dxp_default_portlets.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/sitemap-magento.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/magento-all-levels.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/magento.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/mautic-all-levels.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/mautic.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/modx-all-levels.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/modx-revolution-plugins'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/modx.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/nopcommerce-all-levels.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/nopcommerce.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/octobercms-all-levels.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/octobercms.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/opencart-all-levels.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/opencart.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/opensourcepos-all-levels.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/opensourcepos.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/Oracle-EBS-wordlist.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/pagekit-all-levels.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/pagekit.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/php-nuke.fuzz.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/phpbb-all-levels.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/phpbb.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/pico-all-levels.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/pico.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/piwik-3.0.4.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/prestashop-all-levels.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/prestashop.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/pyrocms-all-levels.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/pyrocms.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/README.md'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/SAP.fuzz.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/Sharepoint-Ennumeration.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/Sharepoint.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/shopware-all-levels.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/shopware.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/shopware1.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/sitecore'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/Sitefinity-fuzz.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/SiteMinder.fuzz.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/snipe-it-all-levels.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/snipe-it.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/statamic-all-levels.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/statamic.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/strapi-all-levels.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/strapi.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/suitecrm-all-levels.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/suitecrm.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/sylius-all-levels.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/sylius.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/symfony-315-demo.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/symphony-267-xslt-cms.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/tomcat-all-levels.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/tomcat.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/umbraco-cms-all-levels.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/umbraco-cms.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/Umbraco.fuzz.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/Umbraco.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/vanilla-all-levels.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/vanilla.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/woocommerce-all-levels.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/woocommerce.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/wordpress-all-levels.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/wordpress.fuzz.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/wp_common_theme_files.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/wordpress.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/wp-plugins.fuzz.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/wp_plugins_full.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/wp-themes.fuzz.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/wp_themes_other.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/yetiforcecrm-all-levels.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/yetiforcecrm.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/zammad-all-levels.txt'

ffuf -u "https://target.xyz/FUZZ" -w 'contents/cms_specific/zammad.txt'
```

### Language Specific

```
ffuf -u 'https://target.xyz/FUZZ' -w content/general/raft_large_directories.txt -e <language_extension> -o lang_ext_raft_large_directories.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/general/combined_words.txt -e <language_extension> -o lang_combined_words.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/general/combined_directories.txt -e <language_extension> -o lang_combined_directories.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/language_specific/Common-PHP-Filenames.txt -o Common-PHP-Filenames.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/language_specific/CommonBackdoors-ASP.txt -o CommonBackdoors-ASP.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/language_specific/CommonBackdoors-JSP.txt -o CommonBackdoors-JSP.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/language_specific/CommonBackdoors-PHP.txt -o CommonBackdoors-PHP.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/language_specific/CommonBackdoors-PL.txt -o CommonBackdoors-PL.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/language_specific/ELMAH-Debugger.txt -o ELMAH-Debugger.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/language_specific/golang.txt -o golang.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/language_specific/Java-Spring-Boot.txt -o Java-Spring-Boot.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/language_specific/PHP.fuzz.txt -o PHP.fuzz.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/language_specific/ror.txt -o ror.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/language_specific/php_backdoors.txt -o php_backdoors.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/language_specific/php_tpl_bot_control_panels.txt -o php_tpl_bot_control_panels.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/language_specific/ASP_CommonBackdoors.txt -o ASP_CommonBackdoors.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/language_specific/cfm_logins.txt -o cfm_logins.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/language_specific/jsp_logins.txt -o jsp_logins.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/language_specific/jsp_logins.txt -o jsp_logins.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/language_specific/php_logins.txt -o jsp_logins.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/language_specific/windows-asp_logins.txt -o windows-asp_logins.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/language_specific/windows-asp_logins.txt -o windows-aspx_logins.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/language_specific/aspx.txt -o aspx.fuzzout.json

ffuf -u 'https://target.xyz/FUZZ' -w content/language_specific/jsp.txt -o jsp.fuzzout.json
```

Move all `fuzzout.json` files into a new directory and index them in the `fuzzout.index.txt` file:
```
mkdir fuzzout; mv *.fuzzout.json fuzzout/; cd fuzzout/

ls -l | grep .fuzzout.json | cut -d ' ' -f 9 > fuzzout.index.txt
```
Extract all URLs returning status code 200:
```
while IFS="" read -r line || [ -n "$line" ]; do jq '.results[] | select(.status == 200) | .url' $line | grep -oE '[^"]+' >> fuzzout.urls.txt; done < fuzzout.index.txt
```
Extract all URLs returning status code 403:
```
while IFS="" read -r line || [ -n "$line" ]; do jq '.results[] | select(.status == 403) | .url' $line | grep -oE '[^"]+' >> fuzzout.urls.txt; done < fuzzout.index.txt
```
Then `sort` and `uniq` `fuzzout.urls.txt`:
```
cat fuzzout.urls.txt | sort | uniq > fuzzout.urls1.txt; rm fuzzout.urls.txt; mv fuzzout.urls1.txt fuzzout.urls.txt
```
f
1. Run eyewitness
2. Fuzz language extensions
3. try 403 bypasses with headers, header values, url appends, and server specific 403 bypasses
4. google dork parameters
# API Enumeration
Nuclei:
```
nuclei -u https://target.com -tags api,fuzz,json
```
Documentation discovery with `ffuf`:
```
ffuf -u 'https://target.xyz/FUZZ' -w content/API/swagger.txt

ffuf -u 'https://target.xyz/FUZZ' -w content/API/common_paths.txt
```
Endpoint discovery with `ffuf`:
```
ffuf -u 'https://target.xyz/FUZZ' -w content/API/graphql.txt

ffuf -u 'https://target.xyz/FUZZ' -w content/API/common-api-endpoints-mazen160.txt
```
Endpoint discovery with `kiterunner`:
```

```

1. Documentation Discovery
2. kiterunner
3. arjun parameter enumeration
4. google dork paramters

# Entry Point Enumeration
 1.  parameter enumeration arjun
 2. parameter enumeration paramspider
 3. Burp param miner
 4. Note down each application entry point


---

## Vulnerability Enumeration
### Known Exploits
1. Google search for exploits against fingerprinted technologies (application, server, cms, framework, js libraries).
### Undiscovered Exploits
1. nuclei
2. nikto
3. sqlmap
4. sstimap
5. lfiscanner

# Automation

Automated targeted fingerprinting:
```
nuclei -u https://target.xyz -as
```
Specific fingerprinting:
```
cat urls.txt | nuclei -itags detect,tech,fingerprint,headers,favicon,server,load-balancer,waf,proxy,cdn,database,iis,microsoft,vector-db,extractors -fuzz
```
Language enumeration:
```
cat urls.txt | nuclei -itags php,python,ruby,java,golang,nodejs,asp -fuzz
```
Client side libraries:
```
cat urls.txt | nuclei -itags js-library -fuzz
```
CMS and frameworks:
```
cat urls.txt | nuclei -itags laravel,django,rails,spring,express,wordpress,joomla,drupal,magento,aem,coldfusion,dotnet,zimaos,xwiki,solarwinds,fortinet -fuzz
```
Content enumeration:
```
cat urls.txt | nuclei -itags fuzz -fuzz # master

cat urls.txt | nuclei -itags dir-enum,exposure,backup,panel -fuzz
```
API and developer platform enumeration:
```
cat urls.txt | nuclei -itags api,swagger,openapi,graphql,grpc,websocket,json,fuzz -tags
```
Cloud-native and devops:
```
cat urls.txt | nuclei -itags devops,storage,k8s,kubernetes,terraform,git,argocd,flux,n8n -fuzz
```
Known CVE enumeration:
```
cat urls.txt | nuclei -itags cve -fuzz
```
Configuration:
```
cat urls.txt | nuclei -itags config,ssl -fuzz
nikto https://target.xyz
```
Input handling vulnerability enumeration:
```
cat urls.txt | nuclei -itags dast,generic-fuzz,fuzz -fuzz

cat urls.txt | nuclei -itags sqli,xss,ssrf,lfi,csrf,rce,xxe,ssti,deserialization,nosqli -fuzz
```
Broken access control enumeration:
```
cat urls.txt | nuclei -itags bac,idor -fuzz
```
Client interaction vulnerabilities:
```
cat urls.txt | nuclei -itags redirect,smuggling,cache-poisoning,cors -fuzz
```
LLM stuff:
```
cat urls.txt  nuclei -itags mcp,llm,langchain
```
