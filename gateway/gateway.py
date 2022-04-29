import zlib
import socket
import select
import selectors
import threading
import queue
import time
import datetime
import struct
import weakref
import binascii

import logging

logger = logging.getLogger("can.gateway")

CAN_FD_DLC = [0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 20, 24, 32, 48, 64]
TIME_REF = time.time()

class CANMessage(object):
    ''' CANMessage Object

        CAN (FD) Frame Table : PCAN Virtual Gateway Frames
        manual : https://www.peak-system.com/produktcd/Pdf/English/PCAN-Gateways_Developer-Documentation_eng.pdf

        | Length(byte) | Feild Name     | Descriptions      |
        | 2            | Length         | frame length      |
        | 2            | Message Type   | see MESSAGE_TYPE_ |
        | 8            | Tag            | not used          |
        | 4            | Timestamp Low  | microseconds low  |
        | 4            | Timestamp High | microseconds high |
        | 1            | Channel        | channel (not used)|
        | 1            | DLC            | data length code  |
        | 2            | Flags          | RTR, EXT-ID Flag  |
        | 4            | CAN ID         | can id            |
        | N            | CAN Data       | can data list     |
        | 4            | CRC32          | optional          |
    '''

    MESSAGE_TYPE_CAN            = 0x80
    MESSAGE_TYPE_CAN_WITH_CRC   = 0x81
    MESSAGE_TYPE_CANFD          = 0x90
    MESSAGE_TYPE_CANFD_WITH_CRC = 0x91

    FLAGS_RTR   = 0x01
    FLAGS_EXTID = 0x02
    FLAGS_FD_EXTID=0x02
    FLAGS_FD_EXTDATA_LENGTH=0x10
    FLAGS_FD_BITRATE_SWITCHING=0x20
    FLAGS_FD_ERROR_STATE=0x40

    # ERROR_STATUS_PASSIVE = 0
    # ERROR_STATUS_WARNING = 1
    # ERROR_STATUS_BUSOFF = 2

    FRAME_HEADER_LENGTH         = 28

    def __init__(self, can_id = None, can_data = None, channel = 0, timestamp = None, fd = False, brs=False, extid = False, remote=False, error_state_indicator=None, with_crc = False, binary_data = None, *args):
        super(CANMessage, self).__init__(*args)

        if type(can_data) is list:
            can_data = bytes(can_data)

        self.remote = remote
        self.extend_id = extid
        self.can_id = can_id
        self.can_data = can_data
        self.channel = channel
        self.fd = fd
        self.brs = brs # bitrate switching enable
        self.error_state_indicator = error_state_indicator
        self.crc_flag = with_crc
        self.timestamp = None

        if binary_data is not None:
            self.parse_from(binary_data)

    def trace_message(self):
        return '({0}) : channel {1}, can id : {2}, can data {3}'.format(
            self.timestamp, self.channel, self.can_id, self.can_data
        )

    def parse_from(self, binary_data):

        frame_length, \
        message_type, \
        tag, \
        timestamp_low, \
        timestamp_high, \
        channel, \
        dlc, \
        flags, \
        can_id = struct.unpack("!HHQIIBBHI", binary_data[0:28])

        # can time stamp means microsecnods (us) from system started
        timestamp = (timestamp_high << 32 | timestamp_low) * 0.000001
        # logger.debug(dlc)

        can_data_bytes = binary_data[28:28+self.__get_length_from_dlc(dlc)]

        if bool(message_type & 0x01):
            # CRC32 value calculation range : DLC, FLAGS, CAN ID, CAN DATA
            # TODO: check byte order
            #       Calcuation with little endian byte order
            crc_begin = 22
            crc_end = 28 + self.__get_length_from_dlc(dlc)
            crc_value = zlib.crc32(binary_data[crc_begin:crc_end])
            crc_ref_value = struct.unpack("!I", binary_data[-4:0])
            # logger.debug(crc_value, crc_ref_value)
            if crc_value != crc_ref_value:
                raise ValueError

        # parse flags
        self.remote = bool(flags & 0x01)
        self.extend_id = bool(flags & 0x02)
        self.brs = bool(flags & 0x10)
        self.error_state_indicator = bool(flags & 0x40)

        # general parameters
        self.can_data = can_data_bytes # list(can_data)
        self.can_id = can_id
        self.timestamp = timestamp
        self.channel = channel
        self.fd = bool(message_type & 0x90)

    def get_binary(self):

        timestamp = int(self.__get_timestamp() * 1000000.0)

        timestamp_low = timestamp & 0xFFFFFFFF
        timestamp_high = (timestamp >> 32) & 0xFFFFFFFF

        message_header = struct.pack("!HHQIIB",
            self.__get_frame_length(),
            self.__get_message_type(),
            0,  # tag
            timestamp_low, timestamp_high,
            self.__get_channel_idx())

        frame_header = struct.pack("!BHI",
            self.get_dlc(),
            self.__get_flags(),
            self.__get_canid())

        frame_data = self.can_data

        frame_crc = b''
        if self.__is_crc_enable(): # no XOR operation
            frame_crc = zlib.crc32(frame_header + frame_data) 

        raw = message_header + frame_header + frame_data + frame_crc
        if len(raw) != self.__get_frame_length():
            raise ValueError

        return raw

    def __get_canid(self):
        arbitration_id = self.can_id & 0x3FFFFFFF
        rtr = (1 << 29) if self.remote and not self.fd else 0
        extid = (2 << 29) if self.extend_id else 0
        return arbitration_id | rtr | extid

    def __get_channel_idx(self):
        return self.channel

    def __get_frame_length(self):
        length = self.FRAME_HEADER_LENGTH + len(self.can_data)
        return length + 4 if self.__is_crc_enable() else length

    def get_dlc(self):
        length = len(self.can_data)
        if length <= 8:
            return length
        for dlc, nof_bytes in enumerate(CAN_FD_DLC):
            if nof_bytes >= length:
                return dlc
        return 15

        # dlc = len(self.can_data)
        # if dlc > 32:
        #     dlc = 0b1110 + int((dlc - 32) / 16)
        # elif dlc > 8:
        #     dlc = 0b1000 + int((dlc - 8) / 4)
        # return dlc

    def __get_flags(self):
        flag = 0
        if self.fd:
            flag |= 0x02 if self.extend_id else 0x00
            flag |= 0x10 if self.fd else 0x00 # extended data length flag
            flag |= 0x20 if self.brs else 0x00
            flag |= 0x40 if self.error_state_indicator else 0x00
        else:
            flag |= 0x02 if self.extend_id else 0x00
            flag |= 0x01 if self.remote else 0x00

        return flag

    def __get_length_from_dlc(self, dlc):
        return CAN_FD_DLC[dlc]

    def __get_timestamp(self):
        # TODO: convert uint64_t microseconds
        return self.timestamp \
            if self.timestamp is not None \
            else time.time() - TIME_REF
            # datetime.datetime.now().timestamp() * 1000000.0

    def __get_message_type(self):
        fd_code = 0x10 if self.fd is True else 0x00
        crc_code = 0x01 if self.crc_flag is True else 0x00
        return 0x80 + fd_code + crc_code

    def __is_crc_enable(self):
        return self.crc_flag is True

    def __is_fd_enable(self):
        return self.fd is True

class CANGateway(object):
    ''' CANGateway TCP/IP Based CAN Message Router
    '''

    def __init__(self, tx_addr : tuple, rx_addr : tuple, *args):
        super(CANGateway, self).__init__(*args)

        self.channel = 0
        self.tx_queue = queue.Queue(1024)
        self.rx_queue = queue.Queue(1024)

        self.server_address = rx_addr
        self.client_address = tx_addr
        self.server_socket : socket = None
        self.receive_socket : socket = None
        self.transmit_socket : socket = None
        self.selector = selectors.DefaultSelector()
        self.thread = None
        self.callback = None
        self._buffer = b''

    def __del__(self):
        self.close()

    def is_available(self):
        return self.transmit_socket is not None

    def prepare_receive_server(self):
        if self.server_socket is not None:
            raise Exception('server socket already created')

        # TCP Server
        try:
            try:
                self.server_socket = socket.create_server(self.server_address)
            except Exception as e:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    try:
                        sock.bind(self.server_address)
                    except socket.error as err:
                        msg = '%s (while attempting to bind on address %r)' % (err.strerror, self.server_address)
                        raise socket.error(err.errno, msg) from None

                    sock.listen()

                    self.server_socket = sock
                except socket.error:
                    sock.close()
                    raise

            self.selector.register(self.server_socket, selectors.EVENT_READ, self.__accept_handler)
            logger.debug('tcp server creation success')

        except socket.error as e:
            logger.debug('tcp server createion error', e)
            return None

    def reconnect_transmit_client(self, timeout=None):
        if self.transmit_socket is None:
            try:
                self.transmit_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.transmit_socket.connect(self.client_address)
                self.transmit_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                # self.transmit_socket = socket.create_connection(self.client_address, timeout=timeout)
                # self.selector.register(self.transmit_socket, selectors.EVENT_WRITE, self.__transmit_handler)
                logger.debug('transmit_socket is connected', self.transmit_socket)
            except socket.error as e:
                self.transmit_socket = None

        return self.transmit_socket

    def __accept_handler(self, sock, sel, event):

        if self.receive_socket is not None:
            # sel.unregister(self.receive_socket)
            logger.debug('prev recv socket closed : ', self.receive_socket)
            self.receive_socket.close()
            self.receive_socket = None

            if self.transmit_socket is not None:
                # logger.debug('prev transmit socket closed : ', self.transmit_socket)
                self.transmit_socket.close()
                self.transmit_socket = None
                self.reconnect_transmit_client()

        conn, addr = sock.accept()
        logger.debug('new recv socket : socket({}), addr({})'.format(conn, addr))

        self.receive_socket = conn
        self.receive_socekt_addr = addr
        self.receive_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        # sel.register(self.receive_socket, selectors.EVENT_READ, self.__receive_handler)

    def __wait_for_read(self, timeout=None):
        try:
            sock_list, _, _ = select.select([self.receive_socket], [], [], timeout)
            if len(sock_list) == 0:
                return None

            return sock_list[0]
        except Exception as verr:
            return None

        except socket.error as e:
            return None

    def __wait_for_write(self, timeout=None):
        try:
            _, sock_list, _ = select.select([], [self.transmit_socket], [], timeout)
            if len(sock_list) == 0:
                return None

            return sock_list[0]
        except socket.error as e:
            return None

    def __receive_socket_recv(self, size):
        try:
            if self.receive_socket is not None:
                return self.receive_socket.recv(size)
            return b''
        # except socket.error as e:
        except Exception as e:
            return b''

    def __recv_msg(self, timeout=None):
        
        if self.receive_socket is None:
            return None

        started = time.time()
        timeout = timeout if timeout is not None else 0
        time_left = timeout

        while time_left >= 0:

            if len(self._buffer) < 2:
                ready = self.__wait_for_read(time_left)
                if ready is None:
                    # timeout
                    return None

                self._buffer += self.__receive_socket_recv(128)
                break

            time_left = timeout - (time.time() - started)

        while len(self._buffer) > 2:
            frame_length_data = struct.unpack('!H', self._buffer[0:2])
            frame_length = frame_length_data[0]

            if frame_length <= len(self._buffer):
                frame_raw = self._buffer[0:frame_length]
                try:
                    msg = CANMessage(binary_data=frame_raw)
                    self._buffer = self._buffer[frame_length:]
                    return msg
                except:
                    self._buffer = self._buffer[2:]
        return None

    def __send_msg(self, data, timeout = None):

        self.reconnect_transmit_client()
        if self.transmit_socket is None:
            return

        started = time.time()
        # If no timeout is given, poll for availability
        timeout = timeout if timeout is not None else 0
        time_left = timeout

        while time_left >= 0:
            # Wait for write availability
            ready = self.__wait_for_write(time_left) # select.select([], [self.socket], [], time_left)[1]
            if not ready:
                # Timeout
                break

            try:
                sent = self.transmit_socket.send(data)
            except socket.error as e:
                sent = 0

            if sent == len(data):
                return


            # Not all data were sent, try again with remaining data
            data = data[sent:]
            time_left = timeout - (time.time() - started)

    def send_msg(self, msg : CANMessage, timeout = None):
        # self.tx_queue.put(msg, timeout)
        self.__send_msg(msg.get_binary(), timeout=timeout)

    def send_can(self, canid, candata, channel = 0):
        self.send_msg(CANMessage(canid, candata, channel=channel, fd=False))

    def send_canfd(self, canid, candata, channel = 0):
        self.send_msg(CANMessage(canid, candata, channel=channel, fd=True, brs=True))

    def read_msg(self, channel, fd, timeout):
        return self.__recv_msg(timeout)

        # try:
        #     q = self.__get_receive_queue(channel, fd)
        #     if timeout is None:
        #         return q.get_nowait()
        #     else:
        #         return q.get(timeout=timeout)
        # except Exception as e:
        #     return None
        # except queue.Empty:
        #     return None

    def read_can(self, channel = 0, timeout = None) -> CANMessage:
        return self.read_msg(channel, False, timeout)

    def read_canfd(self, channel = 0, timeout = None) -> CANMessage:
        return self.read_msg(channel, True, timeout)

    def close(self):
        self.stop()

        if self.server_socket is not None:
            self.server_socket.close()

        if self.transmit_socket is not None:
            self.transmit_socket.close()

        if self.receive_socket is not None:
            self.receive_socket.close()

    def shutdown(self):
        self.close()

    def poll(self, timeout : float = None):
    
        events = self.selector.select(timeout)
        for key, mask in events:
            callback = key.data
            callback(key.fileobj, self.selector, key.events)

        self.reconnect_transmit_client()

    # TODO: Remove Accept Thread, Reconnection Handling with out thread
    # Thread
    def start(self):
        if self.thread is not None:
            raise Exception("Thread already started.")

        self.stop_request = False
        self.thread = threading.Thread(target=self.__run_thread)
        self.thread.start()

    def stop(self):
        if self.thread is not None:
            self.stop_request = True
            self.thread.join()
            self.thread = None

    def __run_thread(self):
        self.prepare_receive_server()
        while not self.stop_request:
            self.poll(0.1)
            time.sleep(0.1)

            # if not self.tx_queue.empty() and self.transmit_socket is not None:
            #     self.__transmit_handler(self.transmit_socket, self.selector, selectors.EVENT_WRITE)




    def __process_stream(self, buf):

        frames = []

        self._buffer += buf
        while len(self._buffer) >= 2:
            flen = struct.unpack('!H', self._buffer[0:2])[0]
            if flen >= len(self._buffer):
                frames.append(self._buffer[0:flen])
                self._buffer = self._buffer[flen:]

        return frames

    def __receive_handler(self, sock, sel, event):
        try:
                for frame in self.__process_stream(buf):
                    # logger.debug'recv raw :', len(buf), binascii.hexlify(buf))
                    self.__on_receive(buf)
                    if self.transmit_socket is not None:
                        self.transmit_socket.send(buf)
               #      # if self.transmit_socket is not None:
               #      #     self.transmit_socket.send(buf)

        except socket.error as e:
            logger.debug('socket{} error {} (receive_handler)'.format(sock, e))

            sel.unregister(sock)
            sock.close()
            self.receive_socket = None

    def __transmit_handler(self, sock, sel, event):
        if self.tx_queue.qsize() > 0:
            data = self.tx_queue.get()
            try:
                raw = data.get_binary()
                ret = sock.send(raw)
                # logger.debug('send raw :', ret, binascii.hexlify(raw))
            except socket.error as e:
                logger.debug('socket error error (transmit_handler)', e)
                sel.unregister(sock)
                sock.close()
                self.transmit_socket = None

    def __get_receive_queue(self, channel = None, fd = None):
        return self.rx_queue

    def __on_receive(self, binary_data):
        try:
            msg = CANMessage(binary_data=binary_data)
            q = self.__get_receive_queue(msg.channel, msg.fd)
            if q.full():
                q.get()

            q.put_nowait(msg)
            if self.callback is not None:
                self.callback(self, q.qsize())

        except Exception as e:
            logger.debug('invalid CAN Message', e)
