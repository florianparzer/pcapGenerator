import base64
import json
import re
from datetime import datetime
import tempfile


class SiplpReader:
    '''
    Is used to read in the messages from the sipgreped siplp trace and generate json objects from them

    Attributes
        __siplpFile : str
            The Path of the siplp trace file
        __jsonFile : str
            The Path of the json file to which the json Objects are written to
        --limIP : str
            The Lim IP Address of the LIM on which the trace was generated.
    '''
    __siplpFile = ''
    __jsonFile = None
    __limIP = ''

    def __init__(self, filePath:str, jsonFile, limIP:str = '127.0.0.1') -> None:
        super().__init__()
        self.__siplpFile, self.__jsonFile, self.__limIP = filePath, jsonFile, limIP


    def readMessage(self):
        '''
        Message Generator function. Reads one message from the siplpFile and yields it
        To access the messages one can use
            for message in readMessage():
                print(message)
        to iterate over all messages or access with
            gen = readMessage()
            print(next(gen))
        to access only one message
        :return: Generator function
        '''
        pattern = '^-+$'
        sipLineMatcher = re.compile('^\d+: ?(.*)$')
        with open(self.__siplpFile) as myFile:
            message = ''
            for line in myFile:
                line = line.strip()
                if re.search(pattern, line):
                    yield message.strip()
                    message = ''
                else:
                    matcher = sipLineMatcher.match(line)
                    if matcher is not None:
                        sipLine = matcher.group(1)
                        message += f'{matcher.group(1)}\r\n'
                    else:
                        message += f'{line}\r\n'

    def generateJson(self):
        '''
        Json Object Generator function. Gets one message from messageGenerator and converts it to a json object
        To access the messages one can use
            for json in generateJson():
                print(json)
        to iterate over all json objects or access with
            jsonGen = generateJson()
            print(next(jsonGen))
        to access only one json object
        :return: Iterator function
        '''
        #Define Regex for the first two lines for incoming and outgoing messages and define the regex for the beginning of the sip message
        incomingL4Matcher = re.compile('.+, (.+) \(.+\)\r\nIncoming from: \[ V4 ((?:[0-9]{1,3}\.?){4}):(\d+) (\w+) .+')
        outgoingL4Matcher = re.compile('.+, (.+) \(.+\)\r\nOutgoing to: \[ V4 ((?:[0-9]{1,3}\.?){4}):(\d+) (\w+).+\].+via \[ V4 ((?:[0-9]{1,3}\.?){4}):(\d+).+')
        payloadMatcher = re.compile('\r\n\r\n\w.+')
        payload = ''
        for message in self.readMessage():
            jsonMessage = {}
            if matcher := incomingL4Matcher.match(message):
                time = matcher.group(1)
                srcIP = matcher.group(2)
                dstIP = self.__limIP
                #Check if the Protocol is TLS and use TCP
                protocol = matcher.group(4) if matcher.group(4) != 'TLS' else 'TCP'
                srcPort = int(matcher.group(3))
                dstPort = 5061 if matcher.group(4) == 'TLS' else 5060
            elif matcher := outgoingL4Matcher.match(message):
                time = matcher.group(1)
                srcIP = self.__limIP
                dstIP = matcher.group(2)
                # Check if the Protocol is TLS and use TCP
                protocol = 'TCP' if matcher.group(4) == 'TLS' else matcher.group(4)
                srcPort = int(matcher.group(6))
                dstPort = int(matcher.group(3))
            if matcher := payloadMatcher.search(message):
                payload = message[matcher.start():].strip()
                #Check if Payload is a sip message with body
                if '\r\n\r\n' in payload:
                    payload = f'{payload}\r\n'
                else:
                    payload = f'{payload}\r\n\r\n'
                payload = base64.b64encode(payload.encode('utf-8')).decode('ascii')
            #Convert the Datetime to a unix timestamp
            timestamp = datetime.strptime(time, '%Y-%m-%d %H:%M:%S.%f').timestamp()
            jsonMessage['timestamp'] = timestamp
            jsonMessage['srcIP'] = srcIP
            jsonMessage['dstIP'] = dstIP
            jsonMessage['protocol'] = protocol
            jsonMessage['srcPort'] = srcPort
            jsonMessage['dstPort'] = dstPort
            jsonMessage['payload'] = payload

            yield jsonMessage

    def writeJsonFile(self):
        '''
        Gets the json objects from  the generateJson yield iterator and writes them to a json file
        :return: None
        '''
        parentObj = {'messages': []}

        serializedParentObj = json.dumps(parentObj)
        self.__jsonFile.write(f'{serializedParentObj[: serializedParentObj.index("[")]}[\n'.encode('UTF-8'))
        isFirstObject = True
        for jsonObjects in self.generateJson():
            if not isFirstObject:
                self.__jsonFile.write(',\n'.encode('UTF-8'))
            else:
                isFirstObject = False
            self.__jsonFile.write(json.dumps(jsonObjects, indent=6).encode('UTF-8'))
        self.__jsonFile.write(f'{serializedParentObj[serializedParentObj.index("]"):]}\n'.encode('UTF-8'))