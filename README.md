# PcapGenerator
## General
This program generates pcap Files from a source File that contains SIP messages.
The source file can either be a json file or a siplp trace that was formatted with sipgrep. 

## Dependencies
This program uses the scapy module to write the pcap files. It is therefore needed to install the module beforehand 
with the command `pip install scapy`

## Help Page
```bash
usage: pcapGen [-h] [-o [PCAPFILE]] [-j | --json | --no-json] [--version]
               inFile [localIP]

The program generates a pcap File from a source file containing SIP Messages.

positional arguments:
  inFile                Specify the path for the input file
  localIP               Specify the IP for the interface receiving the SIP
                        messages. Only applicable whe inFile is a SIPLP log

options:
  -h, --help            show this help message and exit
  -o [PCAPFILE], --out [PCAPFILE]
                        Specify the path for the output file
  -j, --json, --no-json
                        Specify that the input file is in json format
  --version             show program's version number and exit
```

Example for a source file in json is down below:
```json
{ 'Messages' : [{
            'timestamp' : 10100,    # in milliseconds
            'srcIP' : '192.168.1.1',
            'dstIP' : '192.168.1.2',
            'protocol' : 'udp'
            'srcPort' : 40123,
            'dstPort' : 5060,
            'payload' : '<base64 stuff>' #SIP Message in base64
            },
            {
            'timestamp' : 10200,
            'srcIP' : '192.168.1.1',
            'dstIP' : '192.168.1.3',
            'protocol' : 'tcp'
            'srcPort' : 5060,
            'dstPort' : 40123,
            'payload' : '<base64 stuff>'
            }]
}
The payload is bas64 encoded. At the end of a sip message line is \r\n and there must not be a space before that.
Between sip message header and sip message body are \r\n\r\n. If no body is present the message header still ends with these characters
```
## Author
Florian Parzer