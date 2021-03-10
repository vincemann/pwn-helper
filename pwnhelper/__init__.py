
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
                print("cant receive anything after sending shell command -> no shell")
                print("maybe try higher recv_check_timeout")
                return False
        r = io.recv()
        print("shell check response:")
        print(r)
        if control_text in r:
            print("found control text -> shell open")
            return True
        else:
            print("did not find control text -> no shell")
            return False
    except EOFError:
        print("EOF -> no shell, pipe closed or segfault?")
        return False
