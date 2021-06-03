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


def _arch_letter():
    if "32" in context.arch:
        return "e"
    if "64" in context.arch:
        return "r"
    raise Exception("Unknown arch")


class Debugger:

    def __init__(self, binary, process_list, env=None):
        self.binary = binary
        self.process_list = process_list
        self.__init_context()
        self.__start_session(env)

    def __start_session(self, env=None):
        self.io = pwnlib.gdb.debug(self.process_list, api=True, env=env)
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

    # break after push bp, mov bp,sp
    # -> base pointer will be of called function
    # -> stack frame will be the one of called function
    # return methods stack frame
    def go_into(self, function):
        self.go_to(function)
        while True:
            instruction = self.gdb.execute("x/1i$" + _arch_letter() + "ip", to_string=True)
            self.gdb.execute("next")
            self.gdb.wait()
            if "mov" in instruction and _arch_letter() + "bp" and _arch_letter() + "sp" in instruction:
                break
        return self.gdb.selected_frame()

    # extract hex value from gdb examine output
    @staticmethod
    def value_of_ex(examine_output):
        hex_string = examine_output.split(":")[1].strip()
        return int(hex_string, 16)

    def examine(self, adr, amount_words=1):
        values = []
        for i in range(1, amount_words):
            if self.__getBits() == 32:
                values.append(Debugger.value_of_ex(self.gdb.execute("x/1wx" + hex(adr+(i*context.word_size)), to_string=True)))
            else:
                values.append(Debugger.value_of_ex(self.gdb.execute("x/1gx" + hex(adr+(i*context.word_size)), to_string=True)))
        return values

    def examine_string(self, adr, amount_strings=1):
        values = []
        strings_off = 0
        for i in range(1, amount_strings):
            s = self.gdb.execute("x/1s" + hex(adr + (i+strings_off)), to_string=True)
            strings_off += len(s)
            values.append(s)
        return values

    def examine32(self, adr, amount_words=1):
        values = []
        for i in range(1, amount_words):
            values.append(Debugger.value_of_ex(self.gdb.execute("x/1wx" + hex(adr + (i * 4)), to_string=True)))
        return values

    def execute(self, expr, to_string=True):
        return self.gdb.execute(expr, to_string=to_string)

    def recv(self, numb=None):
        return self.io.recv(numb=numb)

    def recvall(self):
        return self.io.recvall()

    # call break_at func or go_to(func) before this function
    # -> need to be halted at first instruction of function
    # only finds args one word big
    def find_args(self, offsets):
        bits = self.__getBits()
        if bits == 32:
            return self.__find_args32(offsets)
        else:
            return self.__find_args64(offsets)

    def __find_args32(self, offsets):
        args = []
        frame = self.gdb.selected_frame()
        esp = int(frame.read_register("esp"))
        for off in offsets:
            # dont need +4 to skip return address, bc frame.read_register does that smh for me
            arg = self.examine(esp + off*context.word_size)
            args.append(arg)
        if len(args) == 1:
            return args[0]
        return args

    def __find_args64(self, offsets):
        args = []
        arg_registers = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
        frame = self.gdb.selected_frame()
        rsp = int(frame.read_register("rsp"))
        for off in offsets:
            if off <= len(arg_registers):
                args.append(frame.read_register(arg_registers[off]))
            else:
                arg = self.examine(rsp + (off-6) * context.word_size)
                args.append(arg)
                # raise Exception("More than 6 args are still unsupported for 64 bit ")
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
            log.info("gdb thread still running while checking for crash, testing with timed out recv now")
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
        log.info("break at: " + t)
        self.cp.breakpoints.append(t)
        self.gdb.execute("b *" + t)

    # call this if you want to receive data and suspect a crash
    # returns (data, crashed_bool)
    # returns (data,False) if program did not crash
    def crash_recv(self, timeout=1):
        r = self.io.recv(timeout=timeout)
        if r is b"":
            # program cant return emtpy string -> must have timed out
            log.warn("receiving time out when receiving, could be crash")
        crashed = self.has_crashed()
        if crashed:
            return r, True
        return r, False

    # breakpoint=True -> create breakpoint at current ip before creating cp
    def checkpoint(self, breakpoint=False):
        # save bp at current pos
        if breakpoint:
            eip = self.read_register(_arch_letter() + "ip")
            self.breakpoint(eip)
        return self.cp.clone()

    # send must be set by user and must contain all sent from method to checkpoint
    def restore_soft_from_method(self, checkpoint, method, sent):
        self.__restore_soft(method, sent, checkpoint)
        self.cp = checkpoint.clone()

    def restore_soft(self, checkpoint):
        log.info("soft restoring checkpoint")
        self.__restore_soft("main", checkpoint.breakpoints, checkpoint.sent)
        self.cp = checkpoint.clone()

    def __restore_soft(self, method, breakpoints, sent):
        self.gdb.execute("set $" + _arch_letter() + "ip=*" + method)
        # disable all breakpoints except last
        self.gdb.execute("disable breakpoints")
        self.gdb.execute("enable " + str(len(breakpoints)))

        # continue until last breakpoint of checkpoint is hit
        self.__continue_until_sent(sent)
        self.gdb.execute("enable breakpoints")
        self.io.clean(timeout=0)

    @staticmethod
    def __getBits():
        if "32" in context.arch:
            return 32
        if "64" in context.arch:
            return 64
        raise Exception("Unknown arch")

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
        log.info("restoring checkpoint hard")
        self.gdb.quit()
        self.__start_session()
        # create last bp and get there by sending all input
        last_bp = checkpoint.breakpoints[-1]

        self.breakpoint(last_bp)
        self.__continue_until_sent(checkpoint.sent)

        # then restore other breakpoints
        for bp in checkpoint.breakpoints[:1]:
            self.breakpoint(bp)

        log.info("restored")