

class SegfaultReport:

    def __init__(self, raw):
        self.ip = self.__parse_register(raw, "ip")
        self.sp = self.__parse_register(raw, "sp")
        self.time = self.__parse_time(raw)
        # print("time:")
        # print(self.time)
        self.raw = raw

    @staticmethod
    def __parse_register(raw, reg):
        splitted = raw.split(" ")
        i = 0
        for e in splitted:
            if e == reg:
                return int(splitted[i + 1], 16)
            i += 1
        raise Exception("Cant find register " + reg + " in crash report")

    @staticmethod
    def __parse_time(raw):
        return float(raw.split("]")[0][1:].strip())

    def __eq__(self, other):
        """Overrides the default implementation"""
        if isinstance(other, SegfaultReport):
            return self.raw == other.raw
        return False

    def __str__(self):
        return self.raw


class Dmesg:
    def __init__(self, session):
        self.io = session
        report = self.get_report()
        if self.__is_segfault_report(report):
            self.last_report = SegfaultReport(report)
        else:
            self.last_report = None

    @staticmethod
    def __is_segfault_report(report):
        return "segfault" in report

    def get_report(self, n=1):
        return self.io.process("dmesg | tail -n "+str(n), shell=True)\
            .recvall()\
            .decode("utf-8")

    def has_segfaulted(self, binary, log=False):
        report = self.get_report()
        if log:
            print("crash report:" + report)
        if self.__is_segfault_report(report):
            report = SegfaultReport(report)
        else:
            if log:
                print("no segfault report found")
            return False, None
        if self.last_report is not None:
            if report == self.last_report:
                if log:
                    print("found same report as before")
                return False, None
            else:
                if binary in report.raw:
                    self.last_report = report
                    return True, report
                else:
                    return False, None
        else:
            return True, report
