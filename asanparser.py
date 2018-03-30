import sys

class AsanData:
    def __init__(self, data=None, fname=None, depth=5):
        self.fname = fname
        self.data = data 

        self.lines = [s.strip() for s in data.splitlines()]

        self.backtraceLines = [] 
        self.headerLine = ""

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
        while n < len(self.lines):
            line = self.lines[n]
            if line.startswith("#"):
                if "libasan" not in line:
                    self.backtraceLines.append(line) 

            n += 1


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

    def bla(self):
        # backtrace
        # typical:
        # "#0 0x7fb6e9cddb60 in __interceptor_free (/usr/lib/x86_64-linux-gnu/libasan.so.3+0xc6b60)"
        # "#1 0x55f0dffae17a in mg_mqtt_destroy_session ../../mongoose.c:10445"
        # "#2 0x55f0dffae1ad in mg_mqtt_close_session ../../mongoose.c:10451"
        # "#3 0x55f0dffaf162 in mg_mqtt_broker ../../mongoose.c:10587"
        # new:
        # "#0 0x55b0a2 (/home/dobin/ffw/mongoose_mqtt_69/bin/mqtt_broker+0x55b0a2)"
        # "#1 0x55cf04 (/home/dobin/ffw/mongoose_mqtt_69/bin/mqtt_broker+0x55cf04)"
        # "#2 0x55c793 (/home/dobin/ffw/mongoose_mqtt_69/bin/mqtt_broker+0x55c793)"
        btStr = ""
        btArr = []
        # n already defined
        while n < len(self.lines):
            lineSplit = self.lines[n].split(" ")
            if len(lineSplit) <= 3:
                n += 1
                continue
            bt = lineSplit[2] + " " + lineSplit[3]

            # remove most of the path
            bt = re.sub(r'/.*/', "", bt)

            btStr += bt + "\n"
            btArr.append(bt)
            n += 1
        asanData["backtrace"] = btArr

        return asanData


    def __str__(self):
        return "AAA"
	

def main():
    filename = sys.argv[1]

    print "Parsing: " + filename
    fd = open(filename, 'r')
    asanData = AsanData(fd.read(), fname=filename, depth=5)

    print asanData
    print asanData.headerLine
    print "---"
    print asanData.backtraceLines

    fd.close()

if __name__=='__main__':
    main()

