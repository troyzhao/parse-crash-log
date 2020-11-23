import os
import json

finalSymbols = []


fpath = Document.askFile( "Select path to save json file", "block_sym.json", 'save' )
print "select f path ", fpath

doc = Document.getCurrentDocument()
IS32BIT = not doc.is64Bits()

def searchBlockReference(segment, baseAddr, callfuncName = "NoFunc"):
  print "base addr 0x%x" % baseAddr 
  for x in xrange(baseAddr - 24,baseAddr + 24, 2):
    # the addr which point to maybe a block
    r = segment.getReferencesFromAddress( x )
    # print "ref from ", hex( x )
    for addr in r:
      refSeg = doc.getSegmentAtAddress( addr )
      proc = refSeg.getProcedureAtAddress( addr )
      
      if proc:
        startAddr = proc.getEntryPoint()
        name = refSeg.getNameAtAddress( startAddr )
        if IS32BIT:
          if name.find("sub") != -1:
            return True, startAddr, callfuncName + "_block_invoke"
        else:
          if name and name.find("block_invoke") != -1:
            print "find ", hex( startAddr )
            return True, startAddr, name 
      else:
        segmentName, sectionName = getSegmentAndSection( addr )
        name = ""
        if segmentName == "__TEXT" and sectionName == "__text" :
          # it`s in code section, make the function name as block_invoke prefix immediately
          name = callfuncName + "_block_invoke"
          
        if name and name.find("block_invoke") != -1:
          print "find ", hex( addr )
          return True, addr, name
      
  return False,0,0

def getSegmentAndSection( addr ):
  seg = doc.getSegmentAtAddress(addr)
  sectionList = seg.getSectionsList()
  for sec in sectionList:
    if addr > sec.getStartingAddress() and \
      addr < (sec.getStartingAddress() + sec.getLength() ):
      return seg.getName(), sec.getName()
  return seg.getName(), ""

# 1.Stack Block Scan

stackBlockAddr = doc.getAddressForName( "__NSConcreteStackBlock" )
print "stack block symbol addr", hex(stackBlockAddr)

# External Symbols Segment
sbInSegment = doc.getSegmentAtAddress(stackBlockAddr)
refsToSB = sbInSegment.getReferencesOfAddress(stackBlockAddr)

refsToSBAddr = []
for addr in refsToSB:
  seg = doc.getSegmentAtAddress(addr)
  if seg.getName() == "__DATA":
    refsToSBAddr = seg.getReferencesOfAddress(addr)
    break

if len(refsToSBAddr) > 0:
  # refs 
  for i in xrange(0,len(refsToSBAddr)):
    addr = refsToSBAddr[i]
    if IS32BIT: 
      if i <= len(refsToSBAddr)-2:
        print "%x - %x" % (refsToSBAddr[i+1], addr)
        if refsToSBAddr[i+1] - addr <= 12:
          # 32bit armv7 has multip address in a same reference
          print "continue"
          continue
      else:
        addr = refsToSBAddr[i]

    print "fn %x" % addr
    seg = doc.getSegmentAtAddress(addr)
    proc = seg.getProcedureAtAddress( addr )
    if proc:
      procName = seg.getNameAtAddress( proc.getEntryPoint() )

    ret, funcAddr, blockName = searchBlockReference(seg, addr, procName)
    if ret:
      print "name: %s" % blockName
      print 'address: "0x%x"' % funcAddr
      finalSymbols.append( { "name": blockName, "address": ("0x%x" % funcAddr) } )
else:
  print "can`t find stack block define!!"


# 2.Global Block Scan

globalBlockAddr = doc.getAddressForName( "__NSConcreteGlobalBlock" )
print "==== global block addr", hex( globalBlockAddr )
gbInSegment = doc.getSegmentAtAddress(globalBlockAddr)
print "ref segment ", gbInSegment.getName()
# doc.log( "segment %s" % doc.getSegmentAtAddress(globalBlockAddr)  )
refsToGBSymbol = gbInSegment.getReferencesOfAddress( globalBlockAddr )
for gbRef in refsToGBSymbol:
  print "global block addr 0x%x" % (gbRef)
  seg = doc.getSegmentAtAddress( gbRef )
  funcPointOffset = 12 if IS32BIT else 16
  funcPointAddr = gbRef + funcPointOffset
  print "func point addr 0x%x" % funcPointAddr
  refsFromFuncPoint = seg.getReferencesFromAddress( funcPointAddr )
  for funcStartAddr in refsFromFuncPoint:
    print "block func start addr 0x%x" % funcStartAddr
    funcSeg = doc.getSegmentAtAddress( funcStartAddr )
    proc = funcSeg.getProcedureAtAddress( funcStartAddr )
    if proc:
      funcStartAddr = proc.getEntryPoint()
      name = funcSeg.getNameAtAddress( funcStartAddr )
    else: 
      print "!! is not procedure 0x%x" % funcStartAddr
      name = funcSeg.getNameAtAddress( funcStartAddr )

    # if hopper does not parse function which call the block
    # then we search who reference the globalBlock define
    if not name:
      continue
    if name.find("block_invoke") == -1:
      refsToGlobalBlockDef = seg.getReferencesOfAddress( gbRef )
      for funcAddr in refsToGlobalBlockDef:
        funcSeg = doc.getSegmentAtAddress( funcAddr )
        proc = funcSeg.getProcedureAtAddress( funcAddr ) 
        if proc:
          startAddr = proc.getEntryPoint()
          name = funcSeg.getNameAtAddress( startAddr ) + "_block_invoke"
        else:
          print "!!! ERROR is not proc ", hex( funcAddr )
          # print "Instruction 0x%x" % funcSeg.instructionStart( funcAddr )
          name = funcSeg.getNameAtAddress( funcAddr ) + "_block_invoke"
    print "name: %s" % name
    print "address: 0x%x" % funcStartAddr
    finalSymbols.append( { "name": ("%s" % name), "address": ("0x%x" % funcStartAddr) } )

jsonDump = json.dumps( finalSymbols )
# print jsonDump
f = open( fpath, "w" )
f.write( jsonDump )
f.close()


