class Interceptor:
    # called once for every connection after it is established
    def conn_established(self, connId : int, src : str, dst : str) -> None:
        pass

    # called once for every connection after on termination
    def conn_terminated(self, connId : int, src : str, dst : str) -> None:
        pass

    # called tor each data packet sent to the interceptor
    # the bytes returned are passed on to the upstream connection
    # returning an empty bytearray effectively drops the incoming packet
    def intercept(self, connId : int, data : bytearray) -> bytearray:
        return data
