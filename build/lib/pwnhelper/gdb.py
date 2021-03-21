from pwn import *


class Checkpoint:
    def __init__(self, sent, breakpoints):
        self.sent = sent
        self.breakpoints = breakpoints

    @staticmethod
    def new():
        return Checkpoint([], [])

    def clone(self):
        return Checkpoint(self.sent.copy(), self.breakpoints.copy())


class Debugger:

    def __init__(self, binary):
        self.binary = binary
        self.__init_context()
        self.__start_session()

    def __start_session(self):
        self.io = pwnlib.gdb.debug([self.binary], api=True)
        self.gdb = self.io.gdb
        self.cp = Checkpoint.new()

    def __init_context(self):
        # context.clear()
        context.binary = self.binary

    # break in first function adr like 'b* main'
    # stack frame will still be the one of calling function
    def go_to(self, function):
        self.breakpoint(function)
        self.gdb.continue_and_wait()

    # break after push ebp, return methods stack frame
    def go_into(self, function):
        self.go_to(function)
        while True:
            instruction = self.gdb.execute("x/1i$eip", to_string=True)
            self.gdb.execute("next")
            self.gdb.wait()
            if "push" in instruction and "ebp" in instruction:
                break
        return self.gdb.selected_frame()

    # extract hex value from gdb examine output
    @staticmethod
    def value_of_ex(examine_output):
        hex_string = examine_output.split(":")[1].strip()
        return int(hex_string, 16)

    def examine(self, adr, amount_words=1):
        return Debugger.value_of_ex(self.gdb.execute("x/" + str(amount_words) + "wx" + hex(adr), to_string=True))

    # 32 bit calling convention
    # call break_at func or go_to(func) before this function
    # -> need to be halted at first instruction of function
    # only finds args one word big
    def find_args(self, offsets, frame=None):
        args = []
        if frame is None:
            frame = self.gdb.selected_frame()
        esp = int(frame.read_register("esp"))
        for off in offsets:
            # dont need +4 to skip return address, bc frame.read_register does that smh for me
            arg = self.examine(esp + off)
            args.append(arg)
        if len(args) == 1:
            return args[0]
        return args

    def read_register(self, register):
        return int(self.gdb.selected_frame().read_register(register))

    # program must be expected to have hit breakpoint when calling
    def has_crashed(self):
        try:
            return self.__has_crashed()
        except Exception:
            # thread still running error occurs, when program crashed
            print("gdb thread still running while checking for crash, testing with timed out recv now")
            # this line fixes the stuck stdout bug, received data is lost anyways
            self.io.clean()
            return self.__has_crashed()

    def __has_crashed(self):
        r = self.gdb.execute("bt", to_string=True)
        # print("has crashed report")
        # print(r)
        if "printf_core" in r:
            return True
        else:
            return False

    def send(self, input):
        self.cp.sent.append(input)
        self.io.send(input)

    def sendline(self, input):
        self.cp.sent.append(input + b"\n")
        self.io.sendline(input)

    def breakpoint(self, target):
        t = target
        if type(target) == int:
            t = hex(target)
        print("break at: " + t)
        self.cp.breakpoints.append(t)
        self.gdb.execute("b *" + t)

    # call this when you want to receive data and suspect a crash
    # returns (data, crashed_bool)
    # returns (data,False) if program crashed
    def crash_recv(self, timeout=1):
        r = self.io.recv(timeout=timeout)
        if r is b"":
            # program cant return emtpy string -> must have timed out
            print("receiving time out when receiving, could be crash")
        crashed = self.has_crashed()
        if crashed:
            return r, True
        return r, False

    # breakpoint=True -> create breakpoint at current eip before creating cp
    def checkpoint(self, breakpoint=False):
        # save bp at current pos
        if breakpoint:
            eip = self.read_register("eip")
            self.breakpoint(eip)
        return self.cp.clone()

    # send must be set by user and must contain all sent from method to checkpoint
    def restore_soft_from_method(self, checkpoint, method, sent):
        self.__restore_soft(method, sent, checkpoint)
        self.cp = checkpoint.clone()

    def restore_soft(self, checkpoint):
        print("soft restoring checkpoint")
        self.__restore_soft("main", checkpoint.breakpoints, checkpoint.sent)
        self.cp = checkpoint.clone()

    def __restore_soft(self, method, breakpoints, sent):
        self.gdb.execute("set $eip=*" + method)
        # disable all breakpoints except last
        self.gdb.execute("disable breakpoints")
        self.gdb.execute("enable " + str(len(breakpoints)))

        # continue until last breakpoint of checkpoint is hit
        self.__continue_until_sent(sent)
        self.gdb.execute("enable breakpoints")
        self.io.clean(timeout=0)

    def __continue_until_sent(self, sent):
        self.gdb.continue_nowait()

        for send in sent:
            if self.io.can_recv():
                print(self.io.recv())
            self.send(send)
        if self.io.can_recv():
            print(self.io.recv())

        self.gdb.wait()

    def restore_hard(self, checkpoint):
        print("restoring checkpoint hard")
        self.gdb.quit()
        self.__start_session()
        # create last bp and get there by sending all input
        last_bp = checkpoint.breakpoints[-1]

        self.breakpoint(last_bp)
        self.__continue_until_sent(checkpoint.sent)

        # then restore other breakpoints
        for bp in checkpoint.breakpoints[:1]:
            self.breakpoint(bp)

        print("restored")