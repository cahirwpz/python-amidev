import asyncio
import asyncio.subprocess
import signal

from .protocol import DebuggerProtocol, DisassemblyLine
from .debug import Debugger
from .state import Registers


class UaeDebuggerProtocol(DebuggerProtocol):
    def cont(self, addr=None):
        if addr is None:
            self.send('g')
        else:
            self.send('g %08X' % addr)

    def step(self, addr=None):
        if addr is None:
            self.send('t')
        else:
            self.send('t %08X' % addr)

    async def read_memory(self, addr, length):
        # 00000004 00C0 0276 00FC 0818 00FC 081A 00FC 081C  ...v............'
        # 00000014 00FC 081E 00FC 0820 00FC 0822 00FC 090E  ....... ..."....'
        # ...
        self.send('m %x %d' % (addr, (length + 15) / 16))
        lines = await self.recv()
        hexlines = [''.join(line.split()[1:9]) for line in lines]
        return ''.join(hexlines)[:length*2]

    @staticmethod
    def _parse_cpu_state(lines):
        # D0 000424B9   D1 00000000   D2 00000000   D3 00000000
        # D4 00000000   D5 00000000   D6 FFFFFFFF   D7 00000000
        # A0 00CF6D1C   A1 00DC0000   A2 00D40000   A3 00000000
        # A4 00D00000   A5 00FC0208   A6 00C00276   A7 00040000
        # USP  00000000 ISP  00040000
        # T=00 S=1 M=0 X=0 N=0 Z=1 V=0 C=0 IMASK=7 STP=0
        # Prefetch fffc (ILLEGAL) 51c8 (DBcc) Chip latch 00000000
        # 00FC0610 51c8 fffc                DBF .W D0,#$fffc == $00fc060e (F)
        # Next PC: 00fc0614
        regs = Registers()
        for l in lines[:5]:
            l = l.split()
            for n, v in zip(l[0::2], l[1::2]):
                regs[n] = int(v, 16)
        sr = lines[5].split()
        T, S, M, X, N, Z, V, C, IMASK, STP = [f.split('=')[1] for f in sr]
        IMASK = '{:03b}'.format(int(IMASK))
        regs['SR'] = int(T + S + M + '0' + IMASK + '000' + X + N + V + C, 2)
        regs['PC'] = int(lines[7].split()[0], 16)
        return regs

    async def read_all_registers(self):
        self.send('r')
        lines = await self.recv()
        return self._parse_cpu_state(lines)

    async def insert_hwbreak(self, addr):
        self.send('f %X' % addr)
        lines = await self.recv()
        if not lines:
            return False
        return lines[0] == 'Breakpoint added'

    async def remove_hwbreak(self, addr):
        self.send('f %X' % addr)
        lines = await self.recv()
        if not lines:
            return False
        return lines[0] == 'Breakpoint removed'

    async def disassemble(self, addr, n=1):
        # 00FC10BC 33fc 4000 00df f09a      MOVE.W #$4000,$00dff09a
        self.send('d %x %d' % (addr, n))
        lines = await self.recv()
        disassembly = []
        for line in lines:
            pc = int(line[:8].strip(), 16)
            op = ''.join(line[8:34].strip().split()).upper()
            ins = line[34:].strip()
            disassembly.append(DisassemblyLine(pc, op, ins))
        return disassembly

    async def prologue(self):
        lines = await self.recv()
        data = {}
        # Breakpoint at 00C04EB0
        if lines[0].startswith('Breakpoint'):
            line = lines.pop(0)
            data['break'] = int(line.split()[2], 16)
        # just processor state
        data['regs'] = self._parse_cpu_state(lines)
        return data

    async def kill(self):
        self.send('q')
        await self.recv()


class UaeProcess(asyncio.SubprocessProtocol):
    def __init__(self, loop, exited):
        self.loop = loop
        self.transport = None
        self.exited = exited

        self._stdout = ''
        self._stderr = ''
        self.stdin = None
        self.stderr = asyncio.Future()

    def dbg_break(self):
        self.transport.send_signal(signal.SIGINT)
        print('')

    def dbg_send(self, cmd):
        cmd += '\n'
        self.stdin.write(cmd.encode())

    async def dbg_recv(self):
        text = await self.stderr
        self.stderr = asyncio.Future()
        return text

    def handle_log(self, line):
        pass

    def connection_made(self, transport):
        self.transport = transport
        self.stdin = transport.get_pipe_transport(0)

    def pipe_data_received(self, fd, data):
        if fd == 1:
            self._stdout += data.decode(errors='ignore')
            while '\n' in self._stdout:
                line, self._stdout = self._stdout.split('\n', 1)
                self.handle_log(line)

        if fd == 2:
            self._stderr += data.decode(errors='ignore')
            if self._stderr[-1] == '>':
                text = self._stderr[:-1]
                lines = [line.strip() for line in text.splitlines()]
                self.stderr.set_result(lines)
                self._stderr = ''

    def process_exited(self):
        self.exited.set_result(True)


async def UaeLaunch(loop, *args, **kwargs):
    process = kwargs.get('process', UaeProcess)
    protocol = kwargs.get('protocol', UaeDebuggerProtocol)

    exited = asyncio.Future()

    # Create the subprocess, redirect the standard I/O to respective pipes
    uae_transport, uae_protocol = await loop.subprocess_exec(
            lambda: process(loop, exited), 'fs-uae', *args)

    debug_protocol = protocol(uae_protocol.dbg_recv, uae_protocol.dbg_send)

    debug_task = asyncio.ensure_future(Debugger(debug_protocol).run())

    # Call FS-UAE debugger on CTRL+C
    loop.add_signal_handler(signal.SIGINT, uae_protocol.dbg_break)

    await exited

    uae_transport.close()
    debug_task.cancel()
