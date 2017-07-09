import socket

# Get raw data method
def get_rawMsg(server, msg, port=43):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect( ( server, port) )
    sendStr = msg + "\r\n"
    sock.send(bytes(sendStr, 'utf-8'))
    buf = ""
    while True:
        data = sock.recv(1024)
        if len(data) == 0:
            break
        buf += str(data)
    return buf
