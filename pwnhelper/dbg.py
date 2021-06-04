from pwn import *
from pwnhelper import *


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

    def __init__(self, process_list, env=None):
        self.binary = process_list[0]
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
        self.remove_last_bp()

    # break after push bp, mov bp,sp
    # -> base pointer will be of called function
    # -> stack frame will be the one of called function
    # return methods stack frame
    # does not always work
    def go_into(self, function):
        self.go_to(function)
        return self.move_into_function()

    # see go_into
    # can be called after go_to to end up at same spot as go_into
    # can be useful for args fetching
    def move_into_function(self):
        while True:
            instruction = self.execute("x/1i$" + self._arch_letter() + "ip")
            # log.info(f"instruction: {instruction}")
            self.gdb.execute("next")
            self.wait()
            if \
                    ("mov" in instruction)\
                    and (self._arch_letter() + "bp" in instruction) \
                    and (self._arch_letter() + "sp" in instruction):
                break
        return self.gdb.selected_frame()

    def wait(self):
        self.gdb.wait()

    def read_base_pointer(self):
        return self.read_register(self._arch_letter()+"bp")

    def read_instruction_pointer(self):
        return self.read_register(self._arch_letter()+"ip")

    def remove_last_bp(self):
        # bp_info = self.execute("info breakpoints")
        # bp_lines = bp_info.split("\n")
        # last_bp_line = bp_lines[len(bp_lines) - 1]
        # log.info("removing bp: " + last_bp_line )
        # #+ " with number: " + str(bp_number)
        # bp_number = int(last_bp_line[0])
        bp_num = len(self.cp.breakpoints)
        self.execute("del "+str(bp_num))

    # extract hex value from gdb examine output
    @staticmethod
    def value_of_ex(examine_output):
        hex_string = examine_output.split(":")[1].strip()
        return int(hex_string, 16)

    # returns adr: value mapping {int,int}
    # if amount words = 1 only value {int} is returned
    def examine(self, adr, amount_words=1):
        values = []
        adressses = []
        for i in range(0, amount_words):
            if context.bits == 32:
                n_target_adr = adr + (i * ((int)(context.word_size / 8)))
                s_target_adr = hex(n_target_adr)
                v = Debugger.value_of_ex(self.execute("x/1wx" + s_target_adr))
                log.info(f"examining dword at adr: {s_target_adr} with value {pad_num_to_hex(v)}")
                values.append(v)
                adressses.append(n_target_adr)
            else:
                n_target_adr = adr + (i * ((int)(context.word_size / 8)))
                s_target_adr = hex(n_target_adr)
                v = Debugger.value_of_ex(self.execute("x/1gx" + s_target_adr))
                log.info(f"examining qword at adr: {s_target_adr} with value {pad_num_to_hex(v)}")
                values.append(v)
                adressses.append(n_target_adr)
        if len(values) == 1:
            return values[0]
        adr_value_map = {}
        for i in range(len(adressses)):
            adr_value_map[adressses[i]] = values[i]
        return adr_value_map

    # see examine
    def examine_string(self, adr, amount_strings=1):
        values = []
        adressses = []
        strings_off = 0
        for i in range(0, amount_strings):
            n_target_adr = adr + (i+strings_off)
            s_target_adr = hex(n_target_adr)
            s = self.execute("x/1s" + s_target_adr)
            log.info(f"examining string at adr: {s_target_adr} with value {s}")
            strings_off += len(s)
            values.append(s)
            adressses.append(n_target_adr)
        if len(values) == 1:
            return values[0]
        adr_value_map = {}
        for i in range(len(adressses)):
            adr_value_map[adressses[i]] = values[i]
        return adr_value_map

    # see examine, force reading 32 bit words
    def examine32(self, adr, amount_words=1):
        values = []
        adressses = []
        for i in range(0, amount_words):
            n_target_adr = adr + (i * 4)
            s_target_adr = hex(n_target_adr)
            v = Debugger.value_of_ex(self.execute("x/1wx" + s_target_adr))
            log.info(f"examining dword at adr: {s_target_adr} with value {pad_num_to_hex32(v)}")
            values.append(v)
            adressses.append(n_target_adr)
        if len(values) == 1:
            return values[0]
        adr_value_map = {}
        for i in range(len(adressses)):
            adr_value_map[adressses[i]] = values[i]
        return adr_value_map

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
        if context.bits == 32:
            return self.__find_args32(offsets)
        else:
            return self.__find_args64(offsets)

    @staticmethod
    def _arch_letter():
        if context.bits == 32:
            return "e"
        if context.bits == 64:
            return "r"

    def __find_args32(self, offsets):
        args = []
        frame = self.gdb.selected_frame()
        esp = int(frame.read_register("esp"))
        for off in offsets:
            # +4 to skip ret adr
            arg = self.examine((esp+4) + off*context.word_size)
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
                # wordsize is 8
                arg = self.examine((rsp+8) + (off-len(arg_registers)) * context.word_size)
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
        r = self.execute("bt")
        # print("has crashed report")
        # print(r)
        if "printf_core" in r:
            return True
        else:
            return False

    # call i.E. after go_to or go_into
    def finish_function(self):
        self.execute("finish")
        self.wait()

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
        # log.info(f"temporary: {temporary}")
        # bp = gdb.Breakpoint(target, temporary=temporary)
        # log.info(f"bp object: {bp}")
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
            eip = self.read_register(self._arch_letter() + "ip")
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
        self.gdb.execute("set $" + self._arch_letter() + "ip=*" + method)
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

        self.wait()

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