import os
from analyzemft import mftsession
from analyzemft import mft
from datetime import datetime
import struct
import binascii


"""
*************************************************************************
 MFTFieldsExtractor - a class in charge of extracting file paths from
 the MFT table and parse it. making use of analyzeMFT package.
*************************************************************************
"""


class MFTFieldsExtractor:

    def __init__(self, mft_file_name, desired_extension, ip_address):
        self.mft_file_name = mft_file_name
        self.desired_extension = desired_extension
        self.ip_address = ip_address
        self.analyzeMFT_session = mftsession.MftSession()

    def build_file_paths(self):
        """
        reading record-by-record from the MFT table, parsing it and building the file paths
        """
        # reset the file reading
        self.analyzeMFT_session.file_mft.seek(0)
        self.analyzeMFT_session.num_records = 0

        # 1024 = 1KB is the size of a record in the MFT table
        raw_record = self.analyzeMFT_session.file_mft.read(1024)
        while raw_record != "":
            minirec = {}
            # parsing the records with an analyzeMFT function
            record = mft.parse_record(raw_record, self.analyzeMFT_session.options)
            minirec['filename'] = record['filename']
            minirec['fncnt'] = record['fncnt']
            if record['fncnt'] == 1:
                minirec['par_ref'] = record['fn', 0]['par_ref']
                minirec['name'] = record['fn', 0]['name']
            if record['fncnt'] > 1:
                minirec['par_ref'] = record['fn', 0]['par_ref']
                for i in (0, record['fncnt'] - 1):
                    if record['fn', i]['nspace'] == 0x1 or record['fn', i]['nspace'] == 0x3:
                        minirec['name'] = record['fn', i]['name']
                if minirec.get('name') is None:
                    minirec['name'] = record['fn', record['fncnt'] - 1]['name']

            self.analyzeMFT_session.mft[self.analyzeMFT_session.num_records] = minirec
            self.analyzeMFT_session.num_records += 1

            # reading the next record
            raw_record = self.analyzeMFT_session.file_mft.read(1024)

    def gen_file_paths_and_print_relevant(self):
        """
        generating the full files paths and printing the paths of files,
        which correspond to the desired file extension.
        """
        for i in self.analyzeMFT_session.mft:
            # if filename starts with / or ORPHAN, we're done.
            # else get filename of parent, add it to ours

            # In case we've not already calculated the full path
            if (self.analyzeMFT_session.mft[i]['filename']) == '':

                if self.analyzeMFT_session.mft[i]['fncnt'] > 0:
                    self.analyzeMFT_session.get_folder_path(i)
                else:
                    self.analyzeMFT_session.mft[i]['filename'] = 'NoFNRecord'

            self.print_relevant_file_paths(self.analyzeMFT_session.mft[i]['filename'])

    def print_relevant_file_paths(self, curr_file_name):
        """
        checks whether curr_file_name is a file with the relevant extension.
        if so, prints to the log the src IP, a timestamp and a full file path.
        :param curr_file_name: the full file path
        """
        if curr_file_name != 'NoFNRecord':
            name, file_extension = os.path.splitext(curr_file_name)
            if file_extension == self.desired_extension:
                print(self.ip_address + " ," + datetime.now().strftime('%H:%M:%S') + " C:" + curr_file_name)

    def extract_files_from_MFT(self):
        """
        extract the paths of files, which correspond to the desired file extension.
        """
        self.initialize_analyzeMFT_session()
        self.build_file_paths()
        self.gen_file_paths_and_print_relevant()

    def initialize_analyzeMFT_session(self):
        """
        initializing a new analyzeMFT session, which would open the MFT file.
        """
        self.analyzeMFT_session.mft_options()
        self.analyzeMFT_session.options.filename = self.mft_file_name
        self.analyzeMFT_session.open_files()


#
#
def decode_data_runs(data_runs):
    """
    static function - decode NTFS data runs from a MFT type 0x80 record.
    more explanation on data runs can be found here:
    http://inform.pucp.edu.pe/~inf232/Ntfs/ntfs_doc_v0.5/concepts/data_runs.html
    """
    decode_pos = 0
    header = data_runs[decode_pos]
    while header != '\x00':
        offset = int(binascii.hexlify(header)[0])
        run_length = int(binascii.hexlify(header)[1])

        # move into the length data for the run
        decode_pos += 1

        length = data_runs[decode_pos:decode_pos + int(run_length)][::-1]
        length = int(binascii.hexlify(length), 16)

        hex_offset = data_runs[decode_pos + run_length:decode_pos + offset + run_length][::-1]
        cluster = twos_comp(int(binascii.hexlify(hex_offset), 16), offset * 8)

        yield length, cluster
        decode_pos = decode_pos + offset + run_length
        header = data_runs[decode_pos]


def twos_comp(val, bits):
    """
    static function - compute the 2's compliment of int value val
    """
    if (val & (1 << (bits - 1))) != 0:
        val = val - (1 << bits)
    return val


def decode_atr_header(s):
    """
    static function - decode the MFT attribute headers.
    by analyzeMFT routines.
    :return: dictionary with the decoded MFT attribute headers
    """
    d = {}
    d['type'] = struct.unpack("<L", s[:4])[0]
    if d['type'] == 0xffffffff:
        return d
    d['len'] = struct.unpack("<L", s[4:8])[0]
    d['res'] = struct.unpack("B", s[8])[0]
    d['nlen'] = struct.unpack("B", s[9])[0]
    d['name_off'] = struct.unpack("<H", s[10:12])[0]
    d['flags'] = struct.unpack("<H", s[12:14])[0]
    d['id'] = struct.unpack("<H", s[14:16])[0]
    if d['res'] == 0:
        d['ssize'] = struct.unpack("<L", s[16:20])[0]
        d['soff'] = struct.unpack("<H", s[20:22])[0]
        d['idxflag'] = struct.unpack("<H", s[22:24])[0]
    else:
        d['start_vcn'] = struct.unpack("<d", s[16:24])[0]
        d['last_vcn'] = struct.unpack("<d", s[24:32])[0]
        d['run_off'] = struct.unpack("<H", s[32:34])[0]
        d['compusize'] = struct.unpack("<H", s[34:36])[0]
        d['f1'] = struct.unpack("<I", s[36:40])[0]
        d['alen'] = struct.unpack("<d", s[40:48])[0]
        d['ssize'] = struct.unpack("<d", s[48:56])[0]
        d['initsize'] = struct.unpack("<d", s[56:64])[0]

    return d
