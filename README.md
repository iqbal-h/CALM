# CALM: Cloud Availability and Latency Measurement Tool

## Correction
This is an official repository for the paper "Characterizing the Availability and Latency in AWS Network from the Perspective of Tenant" published in IEEE/ACM Transactions on Networking. The GitHub link provided in the paper is https://github.ncsu.edu/mshahza/CALM. Unfortunately, this link is not accessable outside the parent organization. Therefore, we provide this public repository to make CALM accessible to public.

## Publication
*Characterizing the Availability and Latency in AWS Network from the Perspective of Tenant*

This paper appears in: IEEE/ACM Transactions on Networking
Print ISSN: 1063-6692
Online ISSN: 1558-2566
Digital Object Identifier: 10.1109/TNET.2022.3148701



## Tool
For datacollection, CALM was executed on Ubuntu 16.04 and also tested on Ubuntu 18.04. The dependencies include python3 and [BCC](https://github.com/iovisor/bcc/blob/master/INSTALL.md).

### How to run the tool?

1. Provide the list of IPs in the ip_list.txt for which it is required to collect the ping packets.
2. Run bpftool.py
3. Run the pings in terminals to all the IPs in ip_list.txt.

Once the desired number of pings are sent. Close the terminals sending the pings. Press Ctrl+C to exit the bpftool.py and store the data to file that is still present in its buffer.


## Dataset
For understanding data, the sample dataset is available in folder _sample_dataset_.
The complete dataset is publicly available [here](https://drive.google.com/drive/u/1/folders/1Bv3tpmZYglP-cM8_SVD2NYgAxp8wNGBd).