# Dropbox and McAfee TIE with OpenDXL

## Introduction

Script that will scan every file within your DropBox folder structure and will check against the McAfee GTI reputation using the McAfee Threat Intelligence Exchange server [Link](https://www.mcafee.com/uk/products/threat-intelligence-exchange.aspx).

The project is working with the the [McAfee TIE DXL Python Client Library](https://github.com/opendxl/opendxl-tie-client-python) github project that helps to get an high level wrapper for the TIE Data Exchange Layer API.

![Alt text](https://cloud.githubusercontent.com/assets/24607076/24209161/6ddb8f30-0f1d-11e7-9f26-b8389cc80ca3.png "Structure")

## Setup

#### McAfee OpenDXL SDK

https://www.mcafee.com/us/developers/open-dxl/index.aspx

1. Python SDK Installation [link](https://opendxl.github.io/opendxl-client-python/pydoc/installation.html)
2. Certificate Files Creation [link](https://opendxl.github.io/opendxl-client-python/pydoc/certcreation.html)
3. ePO Certificate Authority (CA) Import [link](https://opendxl.github.io/opendxl-client-python/pydoc/epocaimport.html)
4. ePO Broker Certificates Export  [link](https://opendxl.github.io/opendxl-client-python/pydoc/epobrokercertsexport.html)

See the McAfee Threat Intelligence Exchange (TIE) DXL Python Client Library at the follow link:

https://github.com/opendxl/opendxl-tie-client-python/wiki

#### Python SDK for Dropbox

See the Python SDK for Dropbox API v2 at the follow link:

https://github.com/dropbox/dropbox-sdk-python


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



