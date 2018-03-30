import sys
import re


class AsanData:
    def __init__(self, data=None, fname=None, depth=5):
        self.fname = fname
        self.data = data 

        self.lines = [s.strip() for s in data.splitlines()]

        self.backtraceLines = [] 
        self.backtraceShortLines = [] 
        self.headerLine = ""

        # the actual data
        self.cause = ""
        self.cause_line = ""
        self.faultaddress = 0x0
        self.backtrace = "" 

        self.parseLines()
        self.getCause()
        self.getFaultaddress()


    def parseLines(self):
        # get header line
        # first line is just some ===, the second line is the important one
        self.headerLine = self.lines[1]

        # get backtrace
        n = 0
        line = None
        didStart = False
        while n < len(self.lines):
            line = self.lines[n]
            if line.startswith("#"):
                didStart = True
                if "libasan" not in line:
                    self.backtraceLines.append(line)
                    self.backtraceShortLines.append( self.makeBacktraceLineShort(line))

            # do not take ALL lines, only until first non-# line
            else:
                if didStart:
                    break

            n += 1


    def makeBacktraceLineShort(self, line):
        lineSplit = line.split(" ")
        bt = lineSplit[3] + " " + lineSplit[4]

        # remove most of the path
        bt = re.sub(r'/.*/', "", bt)

        return bt


    def getCause(self):
        if "heap-buffer-overflow" in self.headerLine:
            self.cause = "Heap BoF"

        if "attempting double-free" in self.headerLine:
            self.cause = "DoubleFree"

        if "heap-use-after-free" in self.headerLine:
            self.cause = "UaF"


    def getFaultaddress(self):
        # "==58842==ERROR: AddressSanitizer: heap-buffer-overflow on address
        #   0x60200000eed8 at pc 0x7f2c3ac7b033 bp 0x7ffd1e7630f0 sp 0x7ffd1e762898"
        if 'memcpy-param-overlap' not in self.headerLine:
            mainLine = self.headerLine.split(" ")
            self.faultaddress = int( mainLine[9], 16)
        else: 
            # get by backtrace
            btline = self.backtraceLines[0]
            btlineArr = btline.split(" ")
            btAddr = btlineArr[1]
            self.faultaddress = int (btAddr, 16)


    def __str__(self):
        o = ""
        o += "Cause: " + self.cause + "\n"
        o += "Fault Address: " + str(hex(self.faultaddress)) + "\n"
        o += "Stack trace: " + str(self.backtraceLines) + "\n"
        o += "Stack trace short: " + str(self.backtraceShortLines) + "\n"
        return o
	

def main():
    filename = sys.argv[1]

    print "Parsing: " + filename
    fd = open(filename, 'r')
    asanData = AsanData(fd.read(), fname=filename, depth=5)

    print asanData

    fd.close()

if __name__=='__main__':
    main()

