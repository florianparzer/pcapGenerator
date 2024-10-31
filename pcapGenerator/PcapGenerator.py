from scapy.all import *
from scapy.utils import PcapWriter
import json
import base64


class TcpConnection:
    '''
    Represents a TCP Connection between two applications

    Attributes
        __sockets : list of strings
            the Sockets that are included in the Connection. It has two elements in the format "ip:port".
            It is sorted to always look the same regardless which socket is the source of a packet or the destination
        __firstSeq : integer
            The counter for the sequence number for the Socket in __sockets[0]
        __firstAck : integer
            The counter for the acknowlege number for the Socket in __sockets[0]
        __secondSeq : integer
            The counter for the sequence number for the Socket in __sockets[1]
        __secondAck : integer
            The counter for the acknowlege number for the Socket in __sockets[1]
    '''
    __sockets = None
    __firstSeq = None
    __firstAck = None
    __secondSeq = None
    __secondAck = None

    def __init__(self, socketA: str, socketB: str) -> None:
        '''
        Init function for the object
        :param socketA: str
            One of sockets of the tcp connection
        :param socketB: str
            One of sockets of the tcp connection
        '''
        super().__init__()

        self.__sockets = [socketA, socketB]
        self.__sockets.sort()
        self.__firstSeq, self.__firstAck, self.__secondSeq, self.__secondAck = 1, 1, 1, 1

    def getSockets(self):
        '''
        Function to access the __sockets list
        :return: list of str
        '''
        return self.__sockets

    def setSockets(self, socketA: str, socketB: str):
        '''
        Change the sockets in __sockets. After it is changed the list is sorted again
        :param socketA: str
            One of sockets of the tcp connection
        :param socketB: str
            One of sockets of the tcp connection
        :return: None
        '''
        self.__sockets = [socketA, socketB]
        self.__sockets.sort()

    def increaseFirstSeq(self, value):
        '''
        Increases the sequence number for the socket in __socket[0]
        :param value: integer value by which the sequence number is increased
        :return: None
        '''
        self.__firstSeq += value

    def increaseFirstAck(self, value):
        '''
        Increases the acknowlege number for the socket in __socket[0]
        :param value: integer value by which the acknowlege number is increased
        :return: None
        '''
        self.__firstAck += value

    def increaseSecondSeq(self, value):
        '''
        Increases the sequence number for the socket in __socket[1]
        :param value: integer value by which the sequence number is increased
        :return: None
        '''
        self.__secondSeq += value

    def increaseSecondAck(self, value):
        '''
        Increases the acknowlege number for the socket in __socket[1]
        :param value: integer value by which the acknowlege number is increased
        :return: None
        '''
        self.__secondAck += value

    def setNumbers(self, firstSeq, firstAck, secondSeq, secondAck):
        '''
        changes the values for the sequence and acknowlege numbers
        :param firstSeq: int; The new value for the sequence number for the Socket in __sockets[0]
        :param firstAck: int; The new value for the acknowlege number for the Socket in __sockets[0]
        :param secondSeq: int; The new value for the sequence number for the Socket in __sockets[1]
        :param secondAck: int; The new value for the acknowlege number for the Socket in __sockets[1]
        :return: None
        '''
        self.__firstSeq, self.__firstAck, self.__secondSeq, self.__secondAck = firstSeq, firstAck, secondSeq, secondAck

    def getFistSeq(self):
        '''
        Get the sequence number for the Socket in __sockets[0]
        :return: integer
        '''
        return self.__firstSeq

    def getFistAck(self):
        '''
        Get the acknowlege number for the Socket in __sockets[0]
        :return: integer
        '''
        return self.__firstAck

    def getSecondSeq(self):
        '''
        Get the sequence number for the Socket in __sockets[1]
        :return: integer
        '''
        return self.__secondSeq

    def getSecondAck(self):
        '''
        Get the acknowlege number for the Socket in __sockets[1]
        :return: integer
        '''
        return self.__secondAck

    def __eq__(self, other: object) -> bool:
        '''
        Compares two TcpConections
        :param other: the other object that is compared to self
        :return: boolean
        '''
        if not isinstance(other, TcpConnection):
            return False
        if self.__sockets == other.__sockets:
            return True

    def __str__(self) -> str:
        '''
        Converts the TcpConnection to a string
        :return: string
        '''
        return self.__sockets[0] + "|" + self.__sockets[1]

    def __hash__(self) -> int:
        '''
        Converts the TcpConnection to a hash value
        :return: integer
        '''
        return hash(f'{self}')


class PcapGenerator:
    '''
    Is used to genereate a PCAP file out of a json object

    Attributes
        __tcpConnections : list of TcpConnection
            Contains the TcpConnections that occur in the messages. Is used to have accurate sequence and acknowlege numbers
        --jsonFile : str
            The path of the file in which the json object of the messages are contained. An example for the json object is down below
        --pcapFile : str
            The path of the file in which the pcap messages are written to

    JSON Example
        { 'Messages' : [{
                    'timestamp' : 10100,    # in milliseconds
                    'srcIP' : '10.207.10.10',
                    'dstIP' : '10.207.10.40',
                    'protocol' : 'udp'
                    'srcPort' : 40123,
                    'dstPort' : 5060,
                    'payload' : '<base64 stuff>' #SIP Message in base64
                    },
                    {
                    'timestamp' : 10200,
                    'srcIP' : '10.207.10.40',
                    'dstIP' : '10.207.10.10',
                    'protocol' : 'tcp'
                    'srcPort' : 5060,
                    'dstPort' : 40123,
                    'payload' : '<base64 stuff>'
                    }]
        }
        The payload is bas64 encoded. At the end of a sip message line is \r\n and there must not be a space before that.
        Between sip message header and sip message body are \r\n\r\n. If no body is present the message header still ends with these characters
    '''
    __tcpConnections = {}
    __jsonFile = ""
    __pcapFile = ""

    def __init__(self, jsonFile: str, pcapFile: str) -> None:
        super().__init__()
        self.__pcapFile = pcapFile
        self.__jsonFile = jsonFile

    def createPcap(self):
        '''
        Creates a pcap file with sip messages. The messages are taken from the jsonFile

        :param jsonFile: The source file where the messages are taken from. This is a json file with the in the same format as the Json exampl
        :param pcapFile: The destination pcap file in which the messages are written
        :return: None
        '''
        data = None
        with open(self.__jsonFile) as file:
            data = json.load(file)
        messages = data['messages']
        pcap = PcapWriter(self.__pcapFile, append=True, sync=False)
        for message in messages:
            if message['protocol'].lower() == 'tcp':
                self.writeTcpMessage(message, pcap)
            else:
                self.writeUdpMessage(message, pcap)
    #TODO multiple code, change code so only the udp/tcp package is generated
    def writeUdpMessage(self, message, pcap):
        payload = base64.b64decode(message['payload'])
        # Generate the paket in scapy
        # Different Layers are encapsulatet with /
        scapy_pkt = Ether(src='00:00:0c:01:01:15', dst='00:00:0c:01:01:16') / \
                    IP(src=message['srcIP'], dst=message['dstIP']) / \
                    UDP(sport=message['srcPort'], dport=message['dstPort']) / \
                    payload
        scapy_pkt.time = message['timestamp']
        pcap.write(scapy_pkt)

    def writeTcpMessage(self, message, pcap):
        '''
        Writes a message to a pcap file
        :param message: Is a JSON object that represents a sip message. It contains Layer 3 and 4 information and the
        TCP payload which is the sip message
        :param pcap: the pcap writer. It contains the file where the message is written to and various options
        :return: None
        '''
        tcpConnection = TcpConnection(f'{message["srcIP"]}:{message["srcPort"]}',
                                      f'{message["dstIP"]}:{message["dstPort"]}')
        payload = base64.b64decode(message['payload'])
        key = str(tcpConnection)
        # Check if the tcpConnection was already created
        if key in self.__tcpConnections:
            del tcpConnection
            tcpConnection = self.__tcpConnections[key]
        else:
            self.__tcpConnections[key] = tcpConnection

        # Set the sequence and acknowlege Number for the tcp package
        # Checks which socket sends the package and therefore uses different numbers
        if f'{message["srcIP"]}:{message["srcPort"]}' == tcpConnection.getSockets()[0]:
            sequenceNumber = tcpConnection.getFistSeq()
            acknowlegeNumber = tcpConnection.getFistAck()
        else:
            sequenceNumber = tcpConnection.getSecondSeq()
            acknowlegeNumber = tcpConnection.getSecondAck()
        # Generate the paket in scapy
        # Different Layers are encapsulatet with /
        scapy_pkt = Ether(src='00:00:0c:01:01:15', dst='00:00:0c:01:01:16') / \
                    IP(src=message['srcIP'], dst=message['dstIP']) / \
                    TCP(sport=message['srcPort'], dport=message['dstPort'], \
                        flags='A', seq=sequenceNumber, ack=acknowlegeNumber) / \
                    payload
        scapy_pkt.time = message['timestamp']

        # Set the new sequence and acknowlege numbers
        # Checks which socket has sent the package and therefore which numbers need to be set
        payloadLen = len(payload)
        if f'{message["srcIP"]}:{message["srcPort"]}' == tcpConnection.getSockets()[0]:
            tcpConnection.increaseFirstSeq(payloadLen)
            tcpConnection.increaseSecondAck(payloadLen)
        else:
            tcpConnection.increaseSecondSeq(payloadLen)
            tcpConnection.increaseFirstAck(payloadLen)
        pcap.write(scapy_pkt)
