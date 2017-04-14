# Dropbox and McAfee TIE with OpenDXL

## Introduction

Script that will scan every file within your DropBox folder structure and will check against the McAfee GTI reputation using the McAfee Threat Intelligence Exchange server [Link](https://www.mcafee.com/uk/products/threat-intelligence-exchange.aspx).

The project is working with the the [McAfee TIE DXL Python Client Library](https://github.com/opendxl/opendxl-tie-client-python) github project that helps to get an high level wrapper for the TIE Data Exchange Layer API.

![Alt text](https://cloud.githubusercontent.com/assets/24607076/24969148/a1ae308e-1fa7-11e7-89e5-4f3618aabf8c.png "Structure")

Dropbox does not provide MD5 or SHA1 of the files and to check against an antivirus solution every single content must be downloaded.
There is a way to keep cache of the hash file calculated locally and every time a new scan is needed, it is possible read the variable “hash_content” provided by Dropbox and make a comparison with the local “hash_content” cached. But as Dropbox says regarding the variable, 
 [Link](https://www.dropbox.com/developers/reference/content-hash)
“You can assume that the content_hash field would always be available and we would not change the way to generate it. However in the unlikely case where we decide to change it in the future, we want to keep the transition process as smooth as possible by declaring the field as optional”.
This is a real challenge to the entire project and the main script has been built taking in consideration the random presence of the variable “hash_content” trying to reduce as much as possible the number of file downloads.


## Setup

#### Python SDK for Dropbox

Create a Dropbox application to make API requests and obtaining an access **token**

https://dropbox.com/developers/apps.

See the Python SDK for Dropbox API v2 at the follow link:

https://github.com/dropbox/dropbox-sdk-python


#### McAfee OpenDXL SDK

https://www.mcafee.com/us/developers/open-dxl/index.aspx

McAfee Threat Intelligence Exchange (TIE) DXL Python Client Library at the follow link:

https://github.com/opendxl/opendxl-tie-client-python/wiki

* Certificate Files Creation [link](https://opendxl.github.io/opendxl-client-python/pydoc/certcreation.html)
* ePO Certificate Authority (CA) Import [link](https://opendxl.github.io/opendxl-client-python/pydoc/epocaimport.html)
* ePO Broker Certificates Export  [link](https://opendxl.github.io/opendxl-client-python/pydoc/epobrokercertsexport.html)



#### edit the dxl.conf
```clj
[Certs]
BrokerCertChain=certs/brokercert.crt
CertFile=certs/client.crt
PrivateKey=certs/client.key

[Brokers]
{}={};8883;
```
#### Dropbox public API service

define the **TOKEN** variable inside the **DropboxScanner.py** script.

```
TOKEN = ''
```



Results are shown as follows:


![Alt text](https://cloud.githubusercontent.com/assets/24607076/24756294/16c97eaa-1ad5-11e7-86d7-182c8aa96f78.png "Report")


```
### Max file size scan:10 MB
### DXL connected
### Dropbox connected
### Getting content from Dropbox

File already cached! Updating reputation.
[GTI: Not Set] /Adaptive_Threat_Protection_10_5_0_257_Extension.zip

File already cached! Updating reputation.
[GTI: Not Set] /artgame.exe

New file! Downloading and calculating the HASH...
[GTI: Known malicious] /software/ArtemisTest.exe

New file! Downloading and calculating the HASH...
[GTI: Known trusted] /other/AdmTmpl.dll

File already cached! Updating reputation.
[GTI: Known trusted] /other/adprovider.dll

File already cached! Updating reputation.
[GTI: Known trusted] /other/7z1510-x64.exe

File already cached! Updating reputation.
[GTI: Not Set] /other/putty-custom.exe

File already cached! Updating reputation.
[GTI: Known trusted] /tools/putty.exe

File already cached! Updating reputation.
[GTI: Known trusted] /software/beta/Cisco_WebEx_Add-On.exe

File already cached! Updating reputation.
[GTI: Known trusted] /software/beta/Frhed-1.6.0-Setup.exe


[10] Total file scanned in 10 seconds

[6] Known trusted
[1] Known malicious
[3] Not Set

```



