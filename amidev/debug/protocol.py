class DisassemblyLine():
    def __init__(self, address, opcode, mnemonic):
        self.address = address
        self.opcode = opcode
        self.mnemonic = mnemonic

    @property
    def next_address(self):
        return self.address + len(self.opcode) / 2

    def __str__(self):
        return '%08X %-32s %s' % (self.address, self.opcode, self.mnemonic)


class CommandNotSupported(Exception):
    pass


class CommandFailed(Exception):
    pass


class DebuggerProtocol():
    """
    This interface is roughly based on GDB Remote Serial Protocol described at:
    https://sourceware.org/gdb/onlinedocs/gdb/Remote-Protocol.html
    """
    def __init__(self, recv, send):
        self.recv = recv
        self.send = send

    def cont(self, addr=None):
        """
        -> ‘c [addr]’

        Continue at addr, which is the address to resume.

        If addr is omitted, resume at current address.
        """
        raise CommandNotSupported

    def step(self, addr=None):
        """
        -> ‘s [addr]’

        Single step, resuming at addr.

        If addr is omitted, resume at same address.
        """
        raise CommandNotSupported

    async def read_all_registers(self):
        """
        -> ‘g’
        <- ‘xxxxxxxx00000000xxxxxxxx00000000...’

        Read general registers.

        Each byte of register data is described by two hex digits. The size of
        each register and their position within the ‘g’ packet are determined
        by the GDB internal gdbarch functions.
        """
        raise CommandNotSupported

    async def write_all_registers(self, data):
        """
        -> ‘G XX..’
        <- ‘OK’ | ‘E NN’

        Write general registers.
        """
        raise CommandNotSupported

    def kill(self):
        """
        -> ‘k’

        Kill request.

        The exact effect of this packet is not specified.
        For a bare-metal target, it may power cycle or reset the target system.
        For a single-process target, it may kill that process if possible.
        """
        raise CommandNotSupported

    async def read_memory(self, addr, length):
        """
        -> ‘m addr,length’
        <- ‘XX..’ | ‘E NN’

        Read length addressable memory units starting at address addr.

        Note that addr may not be aligned to any particular boundary.
        """
        raise CommandNotSupported

    async def write_memory(self, addr, data):
        """
        -> ‘m addr,length:XX...’
        <- ‘OK’ | ‘E NN’

        Write length addressable memory units starting at address addr.

        The data is given by XX...; each byte is transmitted as a two-digit
        hexadecimal number.
        """
        raise CommandNotSupported

    async def read_register(self, regnum):
        """
        -> ‘p n’
        <- ‘XX..’ | ‘E NN’ | ‘’

        Read the value of register n; n is in hex.
        """
        raise CommandNotSupported

    async def write_register(self, regnum, value):
        """
        -> ‘P n=r’
        <- ‘OK’ | ‘E NN’

        Write register n with value r.

        The register number n is in hexadecimal, and r contains two hex digits
        for each byte in the register.
        """
        raise CommandNotSupported

    def reset(self):
        """
        -> ‘r’

        Reset the entire system.
        """
        raise CommandNotSupported

    async def insert_hwbreak(self, addr):
        """
        -> ‘Z1,addr’
        <- ‘OK’ | ‘’ | ‘E NN’

        Insert a hardware breakpoint at address addr.
        """
        raise CommandNotSupported

    async def remove_hwbreak(self, addr):
        """
        -> ‘z1,addr’
        <- ‘OK’ | ‘’ | ‘E NN’

        Remove a hardware breakpoint at address addr.
        """
        raise CommandNotSupported

    async def disassemble(self, address, n):
        raise CommandNotSupported

    async def fetch_segments(self):
        raise CommandNotSupported

    async def read_byte(self, addr):
        return int(await self.read_memory(addr, 1), 16)

    async def read_word(self, addr):
        return int(await self.read_memory(addr, 2), 16)

    async def read_long(self, addr):
        return int(await self.read_memory(addr, 4), 16)
