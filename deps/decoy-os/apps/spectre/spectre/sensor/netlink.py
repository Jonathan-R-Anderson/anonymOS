import socket
import struct
import logging
import os
import threading
from typing import Callable, Optional

logger = logging.getLogger("spectre_netlink")

# Netlink constants
NETLINK_CONNECTOR = 11
CN_IDX_PROC = 1
CN_VAL_PROC = 1

# Message types
PROC_CN_MCAST_LISTEN = 1
PROC_CN_MCAST_IGNORE = 2
NLMSG_DONE = 3

# Event types
PROC_EVENT_NONE = 0x00000000
PROC_EVENT_FORK = 0x00000001
PROC_EVENT_EXEC = 0x00000002
PROC_EVENT_EXIT = 0x80000000

class NetlinkProcessMonitor:
    """
    Experimental event-driven process monitor using the Linux Netlink Connector.
    Provides true real-time, zero-gap visibility into fork/exec/exit events.
    Requires root privileges to bind.
    """
    def __init__(self, callback: Callable[[str, int, int], None]):
        self.callback = callback
        self.sock: Optional[socket.socket] = None
        self.running = False
        self._thread: Optional[threading.Thread] = None
        
        if not logger.handlers:
            ch = logging.StreamHandler()
            ch.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
            logger.addHandler(ch)
            logger.setLevel(logging.INFO)

    def _send_listen_msg(self, listen: bool = True):
        op = PROC_CN_MCAST_LISTEN if listen else PROC_CN_MCAST_IGNORE
        nlmsg_len = 16 + 20 + 4
        
        # Pack nlmsghdr
        nlmsghdr = struct.pack("=IHHII", nlmsg_len, NLMSG_DONE, 0, 0, os.getpid())
        
        # Pack cn_msg
        cn_msg = struct.pack("=IIIIHH", CN_IDX_PROC, CN_VAL_PROC, 0, 0, 4, 0)
        
        # Pack op
        data = struct.pack("=I", op)
        
        self.sock.send(nlmsghdr + cn_msg + data)

    def start(self) -> bool:
        """
        Attempts to bind the netlink socket and start the listener thread.
        Returns True if successful, False if insufficient privileges or kernel support.
        """
        try:
            self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, NETLINK_CONNECTOR)
            self.sock.bind((os.getpid(), CN_IDX_PROC))
            self._send_listen_msg(listen=True)
            
            self.running = True
            self._thread = threading.Thread(target=self._listen_loop, daemon=True)
            self._thread.start()
            logger.info("Successfully bound to Netlink Process Connector (Event-driven mode active).")
            return True
        except PermissionError:
            logger.warning("Insufficient privileges to bind Netlink socket. Falling back to polling mode.")
            return False
        except Exception as e:
            logger.warning(f"Failed to initialize Netlink Connector: {e}. Falling back to polling mode.")
            return False

    def stop(self):
        self.running = False
        if self.sock:
            try:
                self._send_listen_msg(listen=False)
                self.sock.close()
            except Exception:
                pass

    def _listen_loop(self):
        while self.running:
            try:
                data = self.sock.recv(1024)
                if not data or len(data) < 36:
                    continue
                
                # Unpack nlmsghdr (16 bytes)
                nlmsg_len, nlmsg_type, flags, seq, pid = struct.unpack("=IHHII", data[:16])
                
                # Unpack cn_msg (20 bytes)
                cn_idx, cn_val, cn_seq, cn_ack, cn_len, cn_flags = struct.unpack("=IIIIHH", data[16:36])
                
                if cn_idx != CN_IDX_PROC or cn_val != CN_VAL_PROC:
                    continue
                
                if len(data) < 36 + 16:
                    continue
                    
                # Unpack proc_event header (what, cpu, timestamp)
                event_type, cpu, ts = struct.unpack("=IIQ", data[36:52])
                
                if event_type == PROC_EVENT_EXEC:
                    proc_pid, proc_tgid = struct.unpack("=ii", data[52:60])
                    self.callback("EXEC", proc_pid, 0)
                elif event_type == PROC_EVENT_FORK:
                    ppid, ptgid, cpid, ctgid = struct.unpack("=iiii", data[52:68])
                    self.callback("FORK", cpid, ppid)
                elif event_type == PROC_EVENT_EXIT:
                    proc_pid, proc_tgid, exit_code, exit_signal = struct.unpack("=iiii", data[52:68])
                    self.callback("EXIT", proc_pid, 0)
                    
            except OSError:
                break
            except Exception as e:
                logger.debug(f"Error parsing netlink message: {e}")
