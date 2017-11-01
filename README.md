# Dropbox and McAfee TIE with OpenDXL

## Introduction

Software that will scan every file within your DropBox folder structure and will check against the McAfee Threat Intelligence Exchange server [Link](https://www.mcafee.com/uk/products/threat-intelligence-exchange.aspx).

The project is working with the the [McAfee TIE DXL Python Client Library](https://github.com/opendxl/opendxl-tie-client-python) github project that helps to get an high level wrapper for the TIE Data Exchange Layer API.

![Alt text](https://cloud.githubusercontent.com/assets/24607076/24969148/a1ae308e-1fa7-11e7-89e5-4f3618aabf8c.png "Structure")

Dropbox doesn't analyse the files that users send and doesn't provide a standard HASH file like the MD5 and the SHA1.

The software is connected to Dropbox on one side and to McAfee Data Exchange Layer on the other side.

It checks the file parameters which are: the file size and the “dropbox Hash”. If there is not already informations stored, the file is downloaded, the MD5 and the SHA1 are calculated and then sent it to Threat Intelligence Exchange through DXL.
Otherwise, if the file has been already cached and no changes have been done, the software contacts directly TIE for any reputations updates. 


![Alt text](https://cloud.githubusercontent.com/assets/24607076/25804893/5e567802-33f5-11e7-97e1-e70c4de65b15.png "Report")


For every dropbox scan, a completed report is created.
The software intentionally does not delete or quarantine files keeping a no invasive scan strategy and preserving the user privacy. So, for instance, service providers can scan dropbox customers files without accessing to it but providing a complete report of the possible threats.
A log file with all the scan details is also generated. 



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

![Alt text](https://cloud.githubusercontent.com/assets/24607076/25804943/9bc94aa2-33f5-11e7-930a-6fa8ab183ee0.png "Report")

