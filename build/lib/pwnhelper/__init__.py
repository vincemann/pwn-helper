from pwn import *

r"""
    Call this, when you suspect that your exploit works and you should have a shell now.



    Arguments:
            always_recvs: set this to True if you would expect to
                        receive data from process when the exploit fails
            recv_check_timeout: How long to wait for receiving answer from shell.
                                Only makes sense if always_recvs is False

"""
def check_for_shell(io, recv_check_timeout=0.1, always_recvs=False, control_text=b"docgil"):
    try:
        io.sendline(b"echo "+control_text)
        if always_recvs is False:
            if io.can_recv(timeout=recv_check_timeout) is False:
                log.info("cant receive anything after sending shell command -> no shell")
                log.info("maybe try higher recv_check_timeout")
                return False
        r = io.recv()
        log.info("shell check response:")
        log.info(r)
        if control_text in r:
            log.info("found control text -> shell open")
            return True
        else:
            log.info("did not find control text -> no shell")
            return False
    except EOFError:
        log.info("EOF -> no shell, pipe closed or segfault?")
        return False


def pad_num_to_hex(value):
    return "0x" + hex(value).replace("0x", "").zfill((int)((context.word_size/8)*2))


def pad_num_to_hex32(value):
    return "0x" + hex(value).replace("0x", "").zfill((int)((32/8)*2))


def pad_num_to_hex64(value):
    return "0x" + hex(value).replace("0x", "").zfill((int)((64/8)*2))


def print_examine_data(dict):
    adrss = list(dict.keys())
    values = list(dict.values())
    for i in range(len(adrss)):
        log.info(f"adr: {pad_num_to_hex(adrss[i])} ->  {pad_num_to_hex(values[i])}")


def print_examine_data32(dict):
    adrss = list(dict.keys())
    values = list(dict.values())
    for i in range(len(adrss)):
        log.info(f"adr: {pad_num_to_hex32(adrss[i])} ->  {pad_num_to_hex32(values[i])}")