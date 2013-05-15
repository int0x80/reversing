# -----------------------------------------------------------
# ida python color script, stay inside the lines
# -----------------------------------------------------------
#
# -----------------------------------------------------------
# auto-load:
#  fuzzynop wrote about auto-loading scripts with ida pro, tl;dr:
#
#  - add ida pro to explorer context menu
#    - create HKEY_CLASSES_ROOT\*\shell\Open in IDA\command
#
#  - set value data <ida> -S<script> %1
#    - ex: C:\IDA\IDA 6.4\idaq.exe -S"C:\IDA\daisu.py" %1
#
#  full steps at fuzzynop.blogspot.com/2013/04/making-ida-pretty-pretty-quickly.html  
# -----------------------------------------------------------
#
# -----------------------------------------------------------
# modifications:
#  - added tracking of functions with non-zeroing XORs for
#      for faster recognition of possible en/decoding funcs
#  - ported anti-debug from andykhonig's ColorIDA.IDC
#  - ported push/ret from andykhonig's ColorIDA.IDC
#  - added stupid comments and variable names
# -----------------------------------------------------------
#
# -----------------------------------------------------------
# based on:
#  - andykhonig: http://practicalmalwareanalysis.com/colorida-idc-2/
#  - mikesiko:   http://practicalmalwareanalysis.com/setcolorssiko-py/
#  - fuzzynop:   https://code.google.com/p/making-malware-go-backwards/
# -----------------------------------------------------------

idaapi.autoWait()
from idautils import *
from idc import *

# -----------------------------------------------------------
# variable initialization
# -----------------------------------------------------------
xref_count  = 0                     # tracking en/decoding funcs
addr_all    = Heads(0, 0xffffffff)  # address range for x86
addr_anti   = []                    # list of anti instructions
addr_call   = []                    # list of call instructions
addr_xor    = []                    # list of non-zeroing XORs
anti_mnems  = [                     # sometimes used for anti-*
    'cpuid',
    'icebp',
    'in',
    'rdtsc',
    'sgdt',
    'sidt',
    'sldt',
    'smsw',
    'str'
]
prev_mnem   = ''                    # used for push/ret tracking
proc_coded  = {}                    # dictionary of functions
                                    # with non-zero XOR and 
                                    # count of XREF to function

# -----------------------------------------------------------
# gooby pls
# -----------------------------------------------------------
for i in addr_all:

  # -----------------------------------------------------------
  # collect calls
  # -----------------------------------------------------------
  if GetMnem(i) == 'call':
    addr_call.append(i)

  elif (GetMnem(i) == 'ret' and prev_mnem == 'push'):
    addr_call.append(i)

  # -----------------------------------------------------------
  # anti-* stuff
  # -----------------------------------------------------------
  elif (GetMnem(i) in anti_mnems):
    addr_anti.append(i)

  elif (GetMnem(i) == 'int'):
    if (GetOpnd(i, 0) == '3' or GetOpnd(i, 0) == '2D'):
      addr_anti.append(i)
    elif (GetOpnd(i, 0) == '80'):
      print "0x%08x: Hack all the things!" % (i)
  
  # -----------------------------------------------------------
  # former ORs
  # -----------------------------------------------------------
  elif GetMnem(i) == 'xor':
    if (GetOpnd(i, 0) != GetOpnd(i, 1)):
      addr_xor.append(i)
      addr_func = GetFunctionAttr(i, FUNCATTR_START)
      if (addr_func and addr_func not in proc_coded):
        for x in XrefsTo(addr_func, 0):
          xref_count = xref_count + 1
        if xref_count:  
          proc_coded[addr_func] = xref_count
          xref_count = 0
  
  # -----------------------------------------------------------
  # store current mnemonic as previous for push/ret check
  # -----------------------------------------------------------
  prev_mnem = GetMnem(i)

# -----------------------------------------------------------
# wat u doin dolan
# -----------------------------------------------------------
print "Number of calls: %d" % (len(addr_call))
for i in addr_call:
  SetColor(i, CIC_ITEM, 0x666666) #grey

print "Number of potential Anti-RE instructions: %d" % (len(addr_anti))
for i in addr_anti:
  print "Anti-RE potential at %x" % i
  SetColor(i, CIC_ITEM, 0x0000ff) #red
 
print "Number of XORs: %d" % (len(addr_xor))
for i in addr_xor:
  SetColor(i, CIC_ITEM, 0x00a5ff) #orange

print "Possible en/decoding functions:"
for i in sorted(proc_coded, key = proc_coded.get, reverse = True):
  print "0x%08x: %d" % (i, proc_coded[i])
