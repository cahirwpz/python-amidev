import asyncio
import asyncio.subprocess
import logging
import signal

from prompt_toolkit import prompt_async
from prompt_toolkit.history import InMemoryHistory


def print_lines(lines):
    for line in lines:
        print(line)


class UaeDebugger():
    history = InMemoryHistory()

    def __init__(self, recv, send, debuginfo):
        self.recv = recv
        self.send = send
        self.debuginfo = debuginfo

    async def do_command(self, cmd):
        self.send(cmd)
        print_lines(await self.recv())

    async def run(self):
        try:
            print_lines(await self.recv())
            while True:
                try:
                    cmd = await prompt_async('(debug) ', history=self.history,
                                              patch_stdout=True)
                    await self.do_command(cmd.strip())
                except EOFError:
                    pass
        except asyncio.CancelledError:
            pass
        except Exception as ex:
            logging.exception('Debugger bug!')


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


async def UaeLaunch(loop, *args, process=None, debugger=None, debuginfo=None):
    if process is None:
        process = UaeProcess

    if debugger is None:
        debugger = UaeDebugger

    exited = asyncio.Future()

    # Create the subprocess, redirect the standard I/O to respective pipes
    transport, protocol = await loop.subprocess_exec(
            lambda: process(loop, exited), 'fs-uae', *args)

    debug_task = asyncio.ensure_future(
            debugger(protocol.dbg_recv, protocol.dbg_send, debuginfo).run())

    # Call FS-UAE debugger on CTRL+C
    loop.add_signal_handler(signal.SIGINT, protocol.dbg_break)

    await exited

    transport.close()
    debug_task.cancel()
