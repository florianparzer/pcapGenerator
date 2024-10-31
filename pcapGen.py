import argparse
import tempfile
from pcapGenerator.PcapGenerator import *
from pcapGenerator.SiplpReader import *


# TODO General error handling

if __name__ == '__main__':
    # Create Argument Parser and add arguments
    parser = argparse.ArgumentParser(
        prog='pcapGen',
        description='The program generates a pcap File from a source file containing SIP Messages.'
    )
    parser.add_argument('inFile', help='Specify the path for the input file')
    parser.add_argument('localIP', nargs='?', default='127.0.0.1',
                        help='Specify the IP for the interface receiving the SIP messages. Only applicable whe inFile is a SIPLP log')
    parser.add_argument('-o', '--out', dest='pcapFile',
                        nargs='?', const='./sip.pcap', default='./sip.pcap',
                        help='Specify the path for the output file')
    parser.add_argument('-j', '--json', dest='isJson', action=argparse.BooleanOptionalAction,
                        help='Specify that the input file is in json format')
    # parser.add_argument('-J', '--jsonOut', help='Generate a JSON File too. Specify the path to the file') TODO json Gen
    # parser.add_argument('-p', '--stdin', help='Read source data from stdin instead of the input file') TODO read from stdin
    # parser.add_argument('-v', '--verbose', help='Verbose logging of what the program does') TODO Verbose logging
    parser.add_argument('--version', action='version', version='%(prog)s 1.0')
    arguments = parser.parse_args()
    print(arguments)
    if (arguments.isJson):
        pcapGen = PcapGenerator(arguments.inFile, arguments.pcapFile)
        pcapGen.createPcap()
    else:
        #TODO Format check for IP
        #TODO Tempfile for json
        jsonFile = tempfile.NamedTemporaryFile()
        reader = SiplpReader(arguments.inFile, jsonFile.name, arguments.localIP)
        reader.writeJsonFile()
        pcapGen = PcapGenerator(jsonFile.name, arguments.pcapFile)
        pcapGen.createPcap()
        jsonFile.close()


