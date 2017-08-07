import asyncio
import linecache
import logging
import os

from prompt_toolkit import prompt_async
from prompt_toolkit.history import InMemoryHistory

from .info import Symbol, SourceLine, DebugInfo
from .state import BreakPoint, Registers


def print_lines(lines):
    for line in lines:
        print(line)


class Debugger():
    history = InMemoryHistory()

    def __init__(self, protocol):
        self.protocol = protocol
        self.debuginfo = None
        self.breakpoints = []
        self.registers = Registers()

    def address_of(self, where):
        try:
            addr = int(where, 16)
        except ValueError:
            addr = None

        if self.debuginfo:
            if addr is None:
                addr = self.debuginfo.ask_source_line(where)
            if addr is None:
                addr = self.debuginfo.ask_symbol(where)
        return addr

    def break_info(self, pc):
        if self.debuginfo:
            return str(self.debuginfo.ask_address(pc))
        return '%08X' % pc

    def break_lookup(self, addr):
        for bp in self.breakpoints:
            if bp.address == addr:
                return addr
        return None

    async def break_show(self, pc):
        print('Stopped at %s:' % self.break_info(pc))
        sl = None
        if self.debuginfo:
            sl = self.debuginfo.ask_address(pc)
        if sl is None or sl.path is None:
            print_lines(await self.protocol.disassemble(pc, 5))
        else:
            for n in range(sl.line - 2, sl.line + 3):
                print(n, linecache.getline(sl.path, n).rstrip())

    async def prologue(self):
        data = await self.protocol.prologue()
        if 'regs' in data:
            self.regs = data['regs']
            print(self.regs)
            print('')
        await self.break_show(self.regs['PC'])

    async def do_cont(self):
        self.protocol.cont()
        print('Continue...')
        await self.prologue()

    async def do_step(self):
        self.protocol.step()
        await self.prologue()

    async def do_memory_read(self, addr, length):
        print(await self.protocol.read_memory(addr, length))

    async def do_break_insert(self, addr):
        if self.break_lookup(addr):
            return
        if not await self.protocol.insert_hwbreak(addr):
            return
        bp = BreakPoint(addr)
        self.breakpoints.append(bp)
        print('Added breakpoint #%d, %s' %
              (bp.number, self.break_info(bp.address)))

    async def do_break_remove(self, addr):
        bp = self.break_lookup(addr)
        if not bp:
            return
        self.breakpoints.remove(bp)
        await self.protocol.remove_hwbreak(addr)
        print('Removed breakpoint #%d' % bp.number)

    def do_break_show(self):
        for bp in sorted(self.breakpoints):
            print('#%d: %s' % (bp.number, self.break_info(bp.address)))

    async def do_disassemble_range(self, addr, end):
        while addr < end:
            line, = await self.protocol.disassemble(addr, 1)
            addr += line.next_address
            print(line)

    async def do_info_registers(self):
        print(await self.protocol.read_all_registers())

    async def do_debuginfo_read(self, filename):
        segments = await self.protocol.fetch_segments()
        debuginfo = DebugInfo.fromFile(filename)
        if debuginfo.relocate(segments):
            self.debuginfo = debuginfo
        else:
            print('Failed to associate debug info from "%s" '
                  'file with task sections!' % filename)

    async def do_where_am_I(self):
        await self.break_show(self.regs['PC'])

    async def do_quit(self):
        await self.protocol.kill()

    async def do_command(self, cmd):
        fs = cmd.split()
        if not fs:
            return
        op, arg = fs[0], fs[1:]
        if op == 'mr':
            await self.do_memory_read(self.address_of(arg[0]), int(arg[1]))
        elif op == 'b':
            await self.do_break_insert(self.address_of(arg[0]))
        elif op == 'bd':
            await self.do_break_remove(self.address_of(arg[0]))
        elif op == 'bl':
            self.do_break_show()
        elif op == 'dr':
            await self.do_disassemble_range(self.address_of(arg[0]),
                                            self.address_of(arg[1]))
        elif op == 'c':
            await self.do_cont()
        elif op == 's':
            await self.do_step()
        elif op == 'ir':
            await self.do_info_registers()
        elif op == 'q':
            await self.do_quit()
        elif op == 'Zf':
            await self.do_debuginfo_read(arg[0])
        elif op == '!':
            await self.do_where_am_I()
        elif op[0] == ':':
            self.protocol.send(cmd[1:])
            print_lines(await self.protocol.recv())
        else:
            print('Unknown command')

    async def run(self):
        try:
            await self.prologue()
            while True:
                try:
                    cmd = await prompt_async('(debug) ', history=self.history,
                                             patch_stdout=True)
                    await self.do_command(cmd.strip())
                except EOFError:
                    await self.do_cont()
                except KeyboardInterrupt:
                    await self.do_quit()
        except asyncio.CancelledError:
            pass
        except Exception as ex:
            logging.exception('Debugger bug!')
