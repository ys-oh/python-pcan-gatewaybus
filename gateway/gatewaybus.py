"""
Enable basic CAN over a PCAN USB device.
"""

import logging
import time
from datetime import datetime

from typing import Optional
from can import CanError, Message, BusABC, CanInitializationError
from can.bus import BusState
from can.util import len2dlc, dlc2len
from queue import Full

from .gateway import CANGateway, CANMessage

# Set up logging
log = logging.getLogger("can.gateway")

class GatewayBus(BusABC):

    CONNECTION_TIMEOUT = 3

    def __init__(
        self,
        channel="localhost:3999,localhost:3999",
        state=BusState.ACTIVE,
        *args,
        **kwargs
    ):
        super().__init__(channel=channel, *args, **kwargs)

        route_tx = kwargs.get("route_tx", None)
        route_rx = kwargs.get("route_rx", None)

        # example channel format
        # host ip : 192.168.1.10
        # remote ip : 192.168.1.11
        # channel = "192.168.1.10:3999,192.168.1.11:3999"
        if route_rx is None or route_tx is None:
            route_rx, route_tx = channel.split(',')

        tx_addr, tx_port = route_tx.split(':')
        rx_addr, rx_port = route_rx.split(':')
        self.route_tx_addr = (tx_addr, int(tx_port))
        self.route_rx_addr = (rx_addr, int(rx_port))

        self.channel_info = str(channel)
        self.fd = kwargs.get("fd", False)
        self._gateway_channel = 0 # channel is not used

        self._gateway = CANGateway(self.route_tx_addr, self.route_rx_addr)
        self._gateway.start()
        self.state = state

        st = time.time()
        while not self._gateway.is_available():
            et = time.time()
            if time.time() - st >= self.CONNECTION_TIMEOUT:
                self._gateway.close()
                raise CanInitializationError('gateway bus connection timeout')

            time.sleep(0.1)

    def _recv_internal(self, timeout):

        log.debug("Trying to read a msg")
        # TODO: apply event object
        msg = None

        if self.fd:
            msg = self._gateway.read_canfd(self._gateway_channel, timeout=timeout)
        else:
            msg = self._gateway.read_can(self._gateway_channel, timeout=timeout)

        if msg is None:
            return None, False

        rx_msg = Message(
            timestamp=msg.timestamp,
            arbitration_id=msg.can_id,
            is_extended_id=msg.extend_id,
            is_remote_frame=msg.remote,
            # is_error_frame=msg.error, # error ignored
            data=msg.can_data,
            is_fd=msg.fd,
            bitrate_switch=msg.brs,
            error_state_indicator=msg.error_state_indicator,
        )

        log.debug('rx : ', rx_msg)
        return rx_msg, False

    def send(self, msg, timeout=None):

        try:
            gw_msg = CANMessage(
                can_id = msg.arbitration_id,
                can_data = msg.data,
                channel=self._gateway_channel,
                # timestamp = msg.timestamp,
                fd = msg.is_fd,
                brs = msg.bitrate_switch,
                extid = msg.is_extended_id,
                remote = msg.is_remote_frame,
                error_state_indicator=msg.error_state_indicator,
            )

            self._gateway.send_msg(gw_msg, timeout)
            log.debug ('tx : ', msg)

        except Full:
            log.warning("send buffer is full")

    def shutdown(self):
        super().shutdown()
        self._gateway.close()

    @property
    def state(self):
        return self._state

    @state.setter
    def state(self, new_state):
        
        if new_state != BusState.ACTIVE:
            log.warning('gatewaybus support only ACTIVE mode..(TODO)')
            return

        # declare here, which is called by __init__()
        self._state = new_state  # pylint: disable=attribute-defined-outside-init

        # # TODO: Impl 
        # if new_state is BusState.ACTIVE:
        #     # turn off PCAN_LISTEN_ONLY mode
        #     # self._gateway.set_listen_only(False)
        #     pass
        # elif new_state is BusState.PASSIVE:
        #     # self._gateway.set_listen_only(True)
        #     # change PCAN_LISTEN_ONLY Mode
        #     pass

    @staticmethod
    def _detect_available_configs():
        channels = []

        interfaces = [
            {"name":"0", "id":0},
            {"name":"1", "id":1}
        ]

        for i in interfaces:
            channels.append(
                {"interface": "gateway", "channel": i["name"], "supports_fd": True}
            )

        return channels


class GatewayBusError(CanError):
    """
    A generic error on a Gateway bus.
    """
