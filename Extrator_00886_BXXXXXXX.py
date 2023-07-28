#!/usr/bin/env python3
####################################################
#                                                  #
#            Nagra 3  Extrator de dados            #
#            Data: 08 de Junho de 2023             #
#                por The onsitbin                  #
#                                                  #
####################################################

import sys
import binascii
import textwrap
import os
from os import path
from os import walk
#from os import listdir
import time

PATH = binascii.hexlify(raw_input("Input DIRECTORY here: ")).decode('hex')

# define how date time will be presented
date = time.strftime("%d.%m.%Y-%H.%M")
print (date)

# define path to the file you want to convert and shows the content of the directory so you can choose your files to process.
path = os.path.join(os.path.expanduser(PATH + "/"))  # , 'test.dat')
mypath = path

# print the dir content
f = []
for (dirpath, dirnames, filenames) in walk(mypath):
	f.extend(filenames)
	f = "\n".join(f[:])
	print f
	break

print "\nPath to files:\n", path
filename0 = str(raw_input('\nInput binary(XXX.bin) file from the list above: ')).encode('hex').decode('hex')
filename = path + filename0
with open(filename, 'rb') as f:
	content = f.read()

######### if you want to print the input data: uncomment the line bellow  ###########
# print(binascii.hexlify(content)).decode('hex').encode('hex').upper()

try:
	with open(filename, 'rb') as f:
		f.seek(0x0, 0)  # 0E0000 if you use extracted block as .bin file change address to 0x0
		data = f.read()
except:
	print "Error reading file:", filename
	sys.exit(2)

DESCRIPTOR = str(binascii.hexlify(data[0:4])).upper()
NUID = str(binascii.hexlify(data[4:8])).upper()
NPROVIDER = str(binascii.hexlify(data[8:10])).upper()
PROVIDERID = str(binascii.hexlify(data[10:12])).upper()
ARCH = str(binascii.hexlify(data[12:14])).upper()
CWKEYDESC = str(binascii.hexlify(data[14:15])).upper()
Hextable = str(binascii.hexlify(data[18:19])).upper()
TLENGHT = str(binascii.hexlify(data[17:18])).upper()

BLOCK = str(binascii.hexlify(data[19:153]))

eCK0 = str(binascii.hexlify(data[19:35])).upper()
eCK1 = str(binascii.hexlify(data[35:51])).upper()
eCK2 = str(binascii.hexlify(data[51:67])).upper()
eCK3 = str(binascii.hexlify(data[67:83])).upper()
eCK4 = str(binascii.hexlify(data[83:99])).upper()
eCK5 = str(binascii.hexlify(data[99:115])).upper()
eCK6 = str(binascii.hexlify(data[115:131])).upper()
eCK7 = str(binascii.hexlify(data[131:147])).upper()
print 
print 'CSCKeyDescriptor: ', DESCRIPTOR, "(LEN of CWPK block)"
print 'NUID: ', NUID
print 'Max Number of Provider IDs: ',NPROVIDER
print 'Provider ID: ', PROVIDERID, "; SysID ", format(int(PROVIDERID, 16))
print 'Security Architecture: ', ARCH
print 'CW Key descriptor: ', CWKEYDESC
print 'Hex bytes: ', Hextable
print 'Storage table length: 0x%0s'% TLENGHT

print 'eCK0:', eCK0
print 'eCK1:', eCK1
print 'eCK2:', eCK2
print 'eCK3:', eCK3
print 'eCK4:', eCK4
print 'eCK5:', eCK5
print 'eCK6:', eCK6
print 'eCK7:', eCK7

print
print "|||||||||||||||||||||||||||||||||||||"
print "|| New datakeys protection level  || "
print "|||||||||||||||||||||||||||||||||||||"
print

############################
separator = "\n"
tab = "    "
block0583_1 = 140
block0583 = str(binascii.hexlify(data[147:149])).upper()
subkey8A0010 = str(binascii.hexlify(data[149:153])).upper()
subkey8A_256 = (binascii.hexlify(data[152:280])).upper()
subkey8A_256a = textwrap.wrap(subkey8A_256, 32)
print block0583
print subkey8A0010[:4], subkey8A0010[4:6], "-----BLOCK 8A -1024-???? "
print separator.join(subkey8A_256a), separator
#print "NEXT counter = ", (block0583_1 + 5) + 135

BB0583_1 = 280
block0583_1 = (binascii.hexlify(data[BB0583_1:(BB0583_1 + 2)])).upper()
subkey9A1020 = (binascii.hexlify(data[(BB0583_1 + 2):(BB0583_1 + 5)])).upper()
subkey8A0100 = (binascii.hexlify(data[(BB0583_1 + 5):((BB0583_1 + 5) + 132)])).upper()
subkey8A0100a = textwrap.wrap(subkey8A0100, 132)
H_KEY0 = subkey8A0100[:6]
L_KEY0 = subkey8A0100[6:64]
H_KEY1 = subkey8A0100[64:70]
L_KEY1 = subkey8A0100[70:128]
H_KEY2 = subkey8A0100[128:134]
L_KEY2 = subkey8A0100[134:192]
H_KEY3 = subkey8A0100[192:198]
L_KEY3 = subkey8A0100[198:256]
print block0583_1
print subkey9A1020[:4], subkey9A1020[4:6], "-----BLOCK 9A/8A"
print H_KEY0[:6], L_KEY0
print H_KEY1[:6], L_KEY1
print H_KEY2[:6], L_KEY2
print H_KEY3[:6], L_KEY3, separator
#print "NEXT counter = ", (BB0583_1 + 5) + 128

BB0583_2 = 413
block0583_2 = (binascii.hexlify(data[BB0583_2:(BB0583_2 + 2)])).upper()
subkey901020 = (binascii.hexlify(data[(BB0583_2 + 2):(BB0583_2 + 5)])).upper()
subkeyD00100 = (binascii.hexlify(data[(BB0583_2 + 5):((BB0583_2 + 5) + 132)])).upper()
subkeyD00100a = textwrap.wrap(subkeyD00100, 132)
H_KEY0 = subkeyD00100[:6]
L_KEY0 = subkeyD00100[6:64]
H_KEY1 = subkeyD00100[64:70]
L_KEY1 = subkeyD00100[70:128]
H_KEY2 = subkeyD00100[128:134]
L_KEY2 = subkeyD00100[134:192]
H_KEY3 = subkeyD00100[192:198]
L_KEY3 = subkeyD00100[198:256]
print block0583_2
print subkey901020[:4], subkey901020[4:6], "-----BLOCK 90/D0"
print H_KEY0[:6], L_KEY0
print H_KEY1[:6], L_KEY1
print H_KEY2[:6], L_KEY2
print H_KEY3[:6], L_KEY3, separator
#print "NEXT counter = ", (BB0583_2 + 5) + 128

BB0583_3 = 546
block0583_3 = (binascii.hexlify(data[BB0583_3:(BB0583_3 + 2)])).upper()
subkey991020 = (binascii.hexlify(data[(BB0583_3 + 2):(BB0583_3 + 5)])).upper()
subkey990100 = (binascii.hexlify(data[(BB0583_3 + 5):((BB0583_3 + 5) + 132)])).upper()
subkey990100a = textwrap.wrap(subkey990100, 132)
H_KEY0 = subkey990100[:6]
L_KEY0 = subkey990100[6:64]
H_KEY1 = subkey990100[64:70]
L_KEY1 = subkey990100[70:128]
H_KEY2 = subkey990100[128:134]
L_KEY2 = subkey990100[134:192]
H_KEY3 = subkey990100[192:198]
L_KEY3 = subkey990100[198:256]
print block0583_3
print subkey991020[:4], subkey991020[4:6], "-----BLOCK 99/99"
print H_KEY0[:6], L_KEY0
print H_KEY1[:6], L_KEY1
print H_KEY2[:6], L_KEY2
print H_KEY3[:6], L_KEY3, separator
#print "NEXT counter = ", (BB0583_3 + 5) + 128

BB0583_4 = 679
block0583_4 = (binascii.hexlify(data[BB0583_4:(BB0583_4 + 2)])).upper()
subkey981020 = (binascii.hexlify(data[(BB0583_4 + 2):(BB0583_4 + 5)])).upper()
subkey880100 = (binascii.hexlify(data[(BB0583_4 + 5):((BB0583_4 + 5) + 132)])).upper()
subkey880100a = textwrap.wrap(subkey880100, 132)
H_KEY0 = subkey880100[:6]
L_KEY0 = subkey880100[6:64]
H_KEY1 = subkey880100[64:70]
L_KEY1 = subkey880100[70:128]
H_KEY2 = subkey880100[128:134]
L_KEY2 = subkey880100[134:192]
H_KEY3 = subkey880100[192:198]
L_KEY3 = subkey880100[198:256]
print block0583_4
print subkey981020[:4], subkey981020[4:6], "-----BLOCK 98/88"
print H_KEY0[:6], L_KEY0
print H_KEY1[:6], L_KEY1
print H_KEY2[:6], L_KEY2
print H_KEY3[:6], L_KEY3, separator
#print "NEXT counter = ", (BB0583_4 + 5) + 128

BB0583_5 = 812
block0583_5 = (binascii.hexlify(data[BB0583_5:(BB0583_5 + 2)])).upper()
subkeyAA2020 = (binascii.hexlify(data[(BB0583_5 + 2):(BB0583_5 + 5)])).upper()
subkey8A0200 = (binascii.hexlify(data[(BB0583_5 + 5):((BB0583_5 + 5) + 132)])).upper()
subkey8A0200a = textwrap.wrap(subkey8A0200, 132)
H_KEY0 = subkey8A0200[:6]
L_KEY0 = subkey8A0200[6:64]
H_KEY1 = subkey8A0200[64:70]
L_KEY1 = subkey8A0200[70:128]
H_KEY2 = subkey8A0200[128:134]
L_KEY2 = subkey8A0200[134:192]
H_KEY3 = subkey8A0200[192:198]
L_KEY3 = subkey8A0200[198:256]
print block0583_5
print subkeyAA2020[:4], subkeyAA2020[4:6], "-----BLOCK AA/8A"
print H_KEY0[:6], L_KEY0
print H_KEY1[:6], L_KEY1
print H_KEY2[:6], L_KEY2
print H_KEY3[:6], L_KEY3, separator
#print "NEXT counter = ", (BB0583_5 + 5) + 128

BB0583_6 = 945
block0583_6 = (binascii.hexlify(data[BB0583_6:(BB0583_6 + 2)])).upper()
subkeyA02020 = (binascii.hexlify(data[(BB0583_6 + 2):(BB0583_6 + 5)])).upper()
subkeyD00200 = (binascii.hexlify(data[(BB0583_6 + 5):((BB0583_6 + 5) + 132)])).upper()
subkeyD00200a = textwrap.wrap(subkeyD00200, 132)
H_KEY0 = subkeyD00200[:6]
L_KEY0 = subkeyD00200[6:64]
H_KEY1 = subkeyD00200[64:70]
L_KEY1 = subkeyD00200[70:128]
H_KEY2 = subkeyD00200[128:134]
L_KEY2 = subkeyD00200[134:192]
H_KEY3 = subkeyD00200[192:198]
L_KEY3 = subkeyD00200[198:256]
print block0583_6
print subkeyA02020[:4], subkeyA02020[4:6], "----BLOCK A0/D0"
print H_KEY0[:6], L_KEY0
print H_KEY1[:6], L_KEY1
print H_KEY2[:6], L_KEY2
print H_KEY3[:6], L_KEY3, separator
#print "NEXT counter = ", (BB0583_6 + 5) + 128

BBBB0583_7 = 1078
blockBB0583_7 = (binascii.hexlify(data[BBBB0583_7:(BBBB0583_7 + 2)])).upper()
subkeyA92020 = (binascii.hexlify(data[(BBBB0583_7 + 2):(BBBB0583_7 + 5)])).upper()
subkey990200 = (binascii.hexlify(data[(BBBB0583_7 + 5):((BBBB0583_7 + 5) + 132)])).upper()
subkey990200a = textwrap.wrap(subkey990200, 132)
H_KEY0 = subkey990200[:6]
L_KEY0 = subkey990200[6:64]
H_KEY1 = subkey990200[64:70]
L_KEY1 = subkey990200[70:128]
H_KEY2 = subkey990200[128:134]
L_KEY2 = subkey990200[134:192]
H_KEY3 = subkey990200[192:198]
L_KEY3 = subkey990200[198:256]
print blockBB0583_7
print subkeyA92020[:4], subkeyA92020[4:6], "-----BLOCK A9/99"
print H_KEY0[:6], L_KEY0
print H_KEY1[:6], L_KEY1
print H_KEY2[:6], L_KEY2
print H_KEY3[:6], L_KEY3, separator
#print "NEXT counter = ", (BBBB0583_7 + 5) + 128

BBBB0583_8 = 1211
blockBB0583_8 = (binascii.hexlify(data[BBBB0583_8:(BBBB0583_8 + 2)])).upper()
subkeyA82020 = (binascii.hexlify(data[(BBBB0583_8 + 2):(BBBB0583_8 + 5)])).upper()
subkey880200 = (binascii.hexlify(data[(BBBB0583_8 + 5):((BBBB0583_8 + 5) + 132)])).upper()
subkey880200a = textwrap.wrap(subkey880200, 132)
H_KEY0 = subkey880200[:6]
L_KEY0 = subkey880200[6:64]
H_KEY1 = subkey880200[64:70]
L_KEY1 = subkey880200[70:128]
H_KEY2 = subkey880200[128:134]
L_KEY2 = subkey880200[134:192]
H_KEY3 = subkey880200[192:198]
L_KEY3 = subkey880200[198:256]
print blockBB0583_8
print subkeyA82020[:4], subkeyA82020[4:6], "-----BLOCK A8/88"
print H_KEY0[:6], L_KEY0
print H_KEY1[:6], L_KEY1
print H_KEY2[:6], L_KEY2
print H_KEY3[:6], L_KEY3, separator
#print "NEXT counter = ", (BBBB0583_8 + 5) + 128

BB0323 = 1344
block0323 = (binascii.hexlify(data[BB0323:(BB0323 + 2)])).upper()
subkey010E10 = (binascii.hexlify(data[(BB0323 + 2):(BB0323 + 5)])).upper()
subkey010E = (binascii.hexlify(data[(BB0323 + 5):((BB0323 + 5) + 32)])).upper()
H_KEY0 = subkey010E[:32]
H_KEY1 = subkey010E[32:64]
print block0323
print subkey010E10[:4], subkey010E10[4:6], "------BLOCK 01"
print tab, H_KEY0
print tab, H_KEY1, separator
#print "NEXT counter = ", (BB0323 + 5) + 32

BB0622 = 1381
block0622 = (binascii.hexlify(data[BB0622:(BB0622 + 2)])).upper()
subkey811000 = (binascii.hexlify(data[(BB0622 + 2):(BB0622 + 4)])).upper()
subkey8110 = (binascii.hexlify(data[(BB0622 + 4):((BB0622 + 4) + 32)])).upper()
H_KEY0 = subkey8110[:32]
H_KEY1 = subkey8110[32:64]
print block0622
print subkey811000, "   -----BLOCK 81"
print tab, H_KEY0
print tab, H_KEY1, separator
#print "NEXT counter = ", (BB0622 + 5) + 31

BB0436 = 1417
block0436 = (binascii.hexlify(data[BB0436:(BB0436 + 2)])).upper()
subkey000010 = (binascii.hexlify(data[(BB0436 + 2):(BB0436 + 5)])).upper()
subkeyXX0000 = (binascii.hexlify(data[(BB0436 + 5):((BB0436 + 5) + 51)])).upper()
H_KEY0 = subkeyXX0000[:2]
L_KEY0 = subkeyXX0000[2:34]
H_KEY1 = subkeyXX0000[34:36]
L_KEY1 = subkeyXX0000[36:68]
H_KEY2 = subkeyXX0000[68:70]
L_KEY2 = subkeyXX0000[70:]
print block0436
print subkey000010[:4], subkey000010[4:6], "-----BLOCK 00"
print H_KEY0[:2], H_KEY0[2:], L_KEY0
print H_KEY1[:2], H_KEY1[2:], L_KEY1
print H_KEY2[:2], H_KEY2[2:], L_KEY2, separator
#print "NEXT counter = ", (BB0436 + 6) + 50

BB0746 = 1473
block0746 = (binascii.hexlify(data[BB0746:(BB0746 + 2)])).upper()
subkey8A10 = (binascii.hexlify(data[(BB0746 + 2):(BB0746 + 4)])).upper()
subkeyXX8A10 = (binascii.hexlify(data[(BB0746 + 4):((BB0746 + 4) + 68)])).upper()
subkeyXX8A10a = textwrap.wrap(subkeyXX8A10, 16)
H_KEY0 = subkeyXX8A10[:2]
L_KEY0 = subkeyXX8A10[2:34]
H_KEY1 = subkeyXX8A10[34:36]
L_KEY1 = subkeyXX8A10[36:68]
H_KEY2 = subkeyXX8A10[68:70]
L_KEY2 = subkeyXX8A10[70:102]
H_KEY3 = subkeyXX8A10[102:104]
L_KEY3 = subkeyXX8A10[104:]
print block0746
print subkey8A10, "-----BLOCK 8A"
print H_KEY0[:2], H_KEY0[2:], L_KEY0
print H_KEY1[:2], H_KEY1[2:], L_KEY1
print H_KEY2[:2], H_KEY2[2:], L_KEY2
print H_KEY3[:2], H_KEY3[2:], L_KEY3, separator
#print "NEXT counter = ", (BB0746 + 6) + 66

BB0724 = 1545
block0724 = (binascii.hexlify(data[BB0724:(BB0724 + 2)])).upper()
subkey8010 = (binascii.hexlify(data[(BB0724 + 2):(BB0724 + 4)])).upper()
subkeyXX8010 = (binascii.hexlify(data[(BB0724 + 4):((BB0724 + 4) + 68)])).upper()
H_KEY0 = subkeyXX8010[:2]
L_KEY0 = subkeyXX8010[2:34]
H_KEY1 = subkeyXX8010[34:36]
L_KEY1 = subkeyXX8010[36:68]
print block0724
print subkey8010, "-----BLOCK 8A"
print H_KEY0[:2], H_KEY0[2:], L_KEY0
print H_KEY1[:2], H_KEY1[2:], L_KEY1, separator
#print "NEXT counter = ", (BB0724 + 6) + 32

BB0744_0 = 1583
block0744_0 = (binascii.hexlify(data[BB0744_0:(BB0744_0 + 2)])).upper()
subkey9A20 = (binascii.hexlify(data[(BB0744_0 + 2):(BB0744_0 + 4)])).upper()
subkey8A0100 = (binascii.hexlify(data[(BB0744_0 + 4):((BB0744_0 + 4) + 132)])).upper()
H_KEY0 = subkey8A0100[:8]
L_KEY0 = subkey8A0100[8:66]
H_KEY1 = subkey8A0100[66:74]
L_KEY1 = subkey8A0100[74:132]
print block0744_0
print subkey9A20[:4], "-----BLOCK 9A/8A "
print H_KEY0[:2], H_KEY0[2:], L_KEY0
print H_KEY1[:2], H_KEY1[2:], L_KEY1, separator
#print "NEXT counter = ", (BB0744_0 + 6) + 64

BB0744_1 = 1653
block0744_1 = (binascii.hexlify(data[BB0744_1:(BB0744_1 + 2)])).upper()
subkey9020 = (binascii.hexlify(data[(BB0744_1 + 2):(BB0744_1 + 4)])).upper()
subkeyD00100 = (binascii.hexlify(data[(BB0744_1 + 4):((BB0744_1 + 4) + 68)])).upper()
H_KEY0 = subkeyD00100[:8]
L_KEY0 = subkeyD00100[8:66]
H_KEY1 = subkeyD00100[66:74]
L_KEY1 = subkeyD00100[74:132]
print block0744_1
print subkey9020[:4], "-----BLOCK 90/D0"
print H_KEY0[:2], H_KEY0[2:], L_KEY0
print H_KEY1[:2], H_KEY1[2:], L_KEY1, separator
#print "NEXT counter = ", (BB0744_1 + 6) + 64

BB0744_2 = 1723
block0744_2 = (binascii.hexlify(data[BB0744_2:(BB0744_2 + 2)])).upper()
subkey9920 = (binascii.hexlify(data[(BB0744_2 + 2):(BB0744_2 + 4)])).upper()
subkey990100 = (binascii.hexlify(data[(BB0744_2 + 4):((BB0744_2 + 4) + 68)])).upper()
H_KEY0 = subkey990100[:8]
L_KEY0 = subkey990100[8:66]
H_KEY1 = subkey990100[66:74]
L_KEY1 = subkey990100[74:132]
print block0744_2
print subkey9920[:4], "-----BLOCK 99/99"
print H_KEY0[:2], H_KEY0[2:], L_KEY0
print H_KEY1[:2], H_KEY1[2:], L_KEY1, separator
#print "NEXT counter = ", (BB0744_2 + 6) + 64

BB0744_3 = 1793
block0744_3 = (binascii.hexlify(data[BB0744_3:(BB0744_3 + 2)])).upper()
subkey9820 = (binascii.hexlify(data[(BB0744_3 + 2):(BB0744_3 + 4)])).upper()
subkey8801300 = (binascii.hexlify(data[(BB0744_3 + 4):((BB0744_3 + 4) + 68)])).upper()
H_KEY0 = subkey8801300[:8]
L_KEY0 = subkey8801300[8:66]
H_KEY1 = subkey8801300[66:74]
L_KEY1 = subkey8801300[74:132]
print block0744_3
print subkey9820[:4], "-----BLOCK 98/88"
print H_KEY0[:2], H_KEY0[2:], L_KEY0
print H_KEY1[:2], H_KEY1[2:], L_KEY1, separator
#print "NEXT counter = ", (BB0744_3 + 6) + 64

BB0744_4 = 1863
block0744_4 = (binascii.hexlify(data[BB0744_4:(BB0744_4 + 2)])).upper()
subkeyBA20 = (binascii.hexlify(data[(BB0744_4 + 2):(BB0744_4 + 4)])).upper()
subkey8A0300 = (binascii.hexlify(data[(BB0744_4 + 4):((BB0744_4 + 4) + 132)])).upper()
subkey8A0300a = textwrap.wrap(subkey8A0300, 132)
H_KEY0 = subkey8A0300[:8]
L_KEY0 = subkey8A0300[8:66]
H_KEY1 = subkey8A0300[66:74]
L_KEY1 = subkey8A0300[74:132]
# H_KEY2 = subkey8A0300[132:140]
# L_KEY2 = subkey8A0300[140:198]
# H_KEY3 = subkey8A0300[198:206]
# L_KEY3 = subkey8A0300[206:]
print block0744_4
print subkeyBA20[:4], "-----BLOCK BA/8A"
print H_KEY0[:2], H_KEY0[2:], L_KEY0
print H_KEY1[:2], H_KEY1[2:], L_KEY1, separator
# print H_KEY2[:2], H_KEY2[2:], L_KEY2
# print H_KEY3[:2], H_KEY3[2:], L_KEY3
#print "NEXT counter = ", (BB0744_4 + 6) + 64

BB0744_5 = 1933
block0744_5 = (binascii.hexlify(data[BB0744_5:(BB0744_5 + 2)])).upper()
subkeyB920 = (binascii.hexlify(data[(BB0744_5 + 2):(BB0744_5 + 4)])).upper()
subkey9903300 = (binascii.hexlify(data[(BB0744_5 + 4):((BB0744_5 + 4) + 132)])).upper()
subkey9903300a = textwrap.wrap(subkey9903300, 132)
H_KEY0 = subkey9903300[:8]
L_KEY0 = subkey9903300[8:66]
H_KEY1 = subkey9903300[66:74]
L_KEY1 = subkey9903300[74:132]
# H_KEY2 = subkey9903300[132:140]
# L_KEY2 = subkey9903300[140:198]
# H_KEY3 = subkey9903300[198:206]
# L_KEY3 = subkey9903300[206:]
print block0744_5
print subkeyB920[:4], "-----BLOCK B0/D0"
print H_KEY0[:2], H_KEY0[2:], L_KEY0
print H_KEY1[:2], H_KEY1[2:], L_KEY1, separator
# print H_KEY2[:2], H_KEY2[2:], L_KEY2
# print H_KEY3[:2], H_KEY3[2:], L_KEY3
#print "NEXT counter = ", (BB0744_5 + 6) + 64

BB0744_6 = 2003
block0744_6 = (binascii.hexlify(data[BB0744_6:(BB0744_6 + 2)])).upper()
subkeyB820 = (binascii.hexlify(data[(BB0744_6 + 2):(BB0744_6 + 4)])).upper()
subkey980300 = (binascii.hexlify(data[(BB0744_6 + 4):((BB0744_6 + 4) + 132)])).upper()
subkey980300a = textwrap.wrap(subkey980300, 132)
H_KEY0 = subkey980300[:8]
L_KEY0 = subkey980300[8:66]
H_KEY1 = subkey980300[66:74]
L_KEY1 = subkey980300[74:132]
# H_KEY2 = subkey980300[132:140]
# L_KEY2 = subkey980300[140:198]
# H_KEY3 = subkey980300[198:206]
# L_KEY3 = subkey980300[206:]
print block0744_6
print subkeyB820[:4], "-----BLOCK B9/99"
print H_KEY0[:2], H_KEY0[2:], L_KEY0
print H_KEY1[:2], H_KEY1[2:], L_KEY1, separator
# print H_KEY2[:2], H_KEY2[2:], L_KEY2
# print H_KEY3[:2], H_KEY3[2:], L_KEY3
#print "NEXT counter = ", (BB0744_6 + 6) + 64

BB0744_7 = 2073
block0744_7 = (binascii.hexlify(data[BB0744_7:(BB0744_7 + 2)])).upper()
subkeyB820 = (binascii.hexlify(data[(BB0744_7 + 2):(BB0744_7 + 4)])).upper()
subkey880300 = (binascii.hexlify(data[(BB0744_7 + 4):((BB0744_7 + 4) + 132)])).upper()
subkey880300a = textwrap.wrap(subkey880300, 132)
H_KEY0 = subkey880300[:8]
L_KEY0 = subkey880300[8:66]
H_KEY1 = subkey880300[66:74]
L_KEY1 = subkey880300[74:132]
# H_KEY2 = subkey880300[132:140]
# L_KEY2 = subkey880300[140:198]
# H_KEY3 = subkey880300[198:206]
# L_KEY3 = subkey880300[206:]
print block0744_7
print subkeyB820[:4], "-----BLOCK B8/88"
print H_KEY0[:2], H_KEY0[2:], L_KEY0
print H_KEY1[:2], H_KEY1[2:], L_KEY1, separator
# print H_KEY2[:2], H_KEY2[2:], L_KEY2
# print H_KEY3[:2], H_KEY3[2:], L_KEY3
#print "NEXT counter = ", (BB0744_7 + 6) + 64

BB0904 = 2143
block0904 = (binascii.hexlify(data[BB0904:(BB0904 + 2)])).upper()
subkey0304 = (binascii.hexlify(data[(BB0904 + 2):(BB0904 + 4)])).upper()
subkey010400 = (binascii.hexlify(data[(BB0904 + 4):((BB0904 + 4) + 137)])).upper()
subkey010400a = textwrap.wrap(subkey010400, 137)
H_KEY0 = subkey010400[:8]
L_KEY0 = subkey010400[8:76]
H_KEY1 = subkey010400[76:144]
L_KEY1 = subkey010400[144:]
# H_KEY2 = subkey010400[132:140]
# L_KEY2 = subkey010400[140:198]
# H_KEY3 = subkey010400[198:206]
# L_KEY3 = subkey010400[206:]
print block0904
print subkey0304[:4], "-----LAST BLOCK"
print H_KEY0[:4], H_KEY0[4:], L_KEY0[:6], L_KEY0[6:10], L_KEY0[10:12], L_KEY0[12:20], L_KEY0[20:],
print H_KEY1[:2], H_KEY1[2:], L_KEY1, separator
# print H_KEY2[:2], H_KEY2[2:], L_KEY2
# print H_KEY3[:2], H_KEY3[2:], L_KEY3
#print "NEXT counter = ", (BB0904 + 6) + 64

# print file to output.txt file
# f = f.open('BLOCK_0AE3.txt', 'a')
# print >> f.write('...\n')
