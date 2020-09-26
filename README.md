# Malicious_File_indexer

Malicious_File_indexer project is the brain behind the next-get ransomware. Instead of encrypting everything on the hard drive, you will only encrypt business-valuable files (it is up to the malicious actor to decide). To do so, you need a way to efficiently target import files. For some organizations valuable files will be word documents (.docx), for some hi-res pictures (.png) and for others their code base (.cs, .cpp, .java, …).

# Explanation of the files:

 Malware.py:
 a class in charge of retrieving the Master File Table (MFT) record for an NTFS file system
 and send it off to the attack server over TCP in a compressed manner.
 serves as an initial stage for the upcoming ransomware
 
 CnCServer.py:
 Command and Control Server. a class in charge of operating a server, which waits for the MFT data from the malware and every newly arrived MFT,
 it will map, according to the users input of desired file extensions, the paths of files, which correspond to the desired file extension.
 prints to the log the src IP, a timestamp and a full file path
 
 MFTFieldsExtractor.py:
 a class in charge of extracting file paths from the MFT table and parse it. making use of analyzeMFT package.
 
 operating EXAMPLE:
  (Operator) >> jpeg [Enter]
  (Output) 192.168.10.1 ,08:00:00 c:\pictures\mom.jpeg
  192.168.10.1 ,08:00:02 c:\pictures\vacation.jpeg
  
  (Operator) >> docx [Enter]
  (Output) 192.168.10.1 ,08:01:00 c:\users\alex\documents\cv.docx
  192.168.10.1 ,08:01:01 c:\users\alex\downloads\recipe.docx

 #  Run Instructions
  the code is written in python 2.7, so please use python 2.7 interpreter in order to run it.
  
  ========
  
  please install the following library:
  analyzeMFT
  installation methods:
      pip install analyzeMFT
      Alternatively:
      git clone https://github.com/dkovar/analyzeMFT.git
      or download it from here: https://pypi.org/project/analyzeMFT 
  
  ========
  
  in order to run the project, you will have to run the CnCServer.py first, and then Malware.py
  running CnCServer.py will activate the Command and Control Server, which will wait for the Malware.py to send it the compressed MFT file.
  after the Malware.py finishes to run, you will have to enter the desired file extension, and the magic will happen.
  the CnCServer.py will stay running waiting for more requests.
