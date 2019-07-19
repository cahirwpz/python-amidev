import os
import re
from collections import namedtuple

from amidev.binfmt import hunk


Segment = namedtuple('Segment', 'start size')


class StabInfoParser():
    # https://sourceware.org/gdb/onlinedocs/stabs/

    Types = namedtuple('Types', 'decls')
    Entry = namedtuple('Entry', 'name value')
    Field = namedtuple('Field', 'name type offset size')
    StructType = namedtuple('StructType', 'size fields')
    UnionType = namedtuple('UnionType', 'size fields')
    EnumType = namedtuple('EnumType', 'values')
    SizeOf = namedtuple('SizeOf', 'size type')
    Subrange = namedtuple('Subrange', 'itype lo hi')
    ArrayType = namedtuple('ArrayType', 'range type')
    Function = namedtuple('Function', 'name attr type')
    FunctionType = namedtuple('FunctionType', 'type')
    Pointer = namedtuple('Pointer', 'type')
    Parameter = namedtuple('Parameter', 'name attr type')
    Register = namedtuple('Register', 'name type')
    Variable = namedtuple('Variable', 'name attr type')
    ForwardDecl = namedtuple('ForwardDecl', 'type name')
    Info = namedtuple('Info', 'name info')
    TypeDecl = namedtuple('TypeDecl', 'name type')

    def __init__(self, typemap):
        self._data = ''
        self._typemap = typemap
        self._pos = 0

    def read(self):
        try:
            char = self._data[self._pos]
            self._pos += 1
            return char
        except IndexError:
            return None

    def unread(self):
        self._pos -= 1

    def expect(self, char):
        try:
            last = self._data[self._pos]
        except IndexError:
            last = None
        if last != char:
            raise ValueError('Expected "%s" got "%s" in "%s"' %
                             (char, self.rest()[0], self._data))
        self._pos += 1

    def consume(self, regex):
        m = regex.match(self._data, self._pos)
        if not m:
            raise ValueError('Expected "%s" got "%s" in "%s"' %
                             (regex.pattern, self.rest(), self._data))
        self._pos = m.end()
        return m.group(0)

    def peek(self, char):
        try:
            last = self._data[self._pos]
        except IndexError:
            last = None
        if last != char:
            return False
        self._pos += 1
        return True

    def rest(self):
        return self._data[self._pos:]

    def addType(self, n, v):
        self._typemap[n] = v
        return v

    TLabel = re.compile('[A-Za-z0-9_ ]+')
    TNumber = re.compile('-?[0-9]+')

    def __Label(self):
        return self.consume(self.TLabel)

    def __Number(self):
        number = self.consume(self.TNumber)
        if number[0] == '0':
            return int(number, 8)
        return int(number)

    def __Field(self):
        name, _ = self.__Label(), self.expect(':')
        typ, _ = self.__TypeDecl(), self.expect(',')
        offset, _ = self.__Number(), self.expect(',')
        size, _ = self.__Number(), self.expect(';')
        return self.Field(name, typ, offset, size)

    def __Type(self):
        last = self.read()

        if last == 'a':
            arange = self.__Type()
            eltype = self.__TypeDecl()
            return self.ArrayType(arange, eltype)

        if last == 'r':
            _of, _ = self.__Number(), self.expect(';')
            _lo, _ = self.__Number(), self.expect(';')
            _hi, _ = self.__Number(), self.expect(';')
            if _lo > 0 and _hi > 0:
                _lo = -_lo
            return self.Subrange(_of, _lo, _hi)

        if last == 's':
            size = self.__Number()
            fields = []
            while not self.peek(';'):
                fields.append(self.__Field())
            return self.StructType(size, fields)

        if last == 'u':
            size = self.__Number()
            fields = []
            while not self.peek(';'):
                fields.append(self.__Field())
            return self.UnionType(size, fields)

        if last == 'f' or last == 'F':
            return self.FunctionType(self.__Number())

        if last == '*':
            return self.Pointer(self.__Type())

        if last == 'x':
            if self.peek('s'):
                typ = 'struct'
            elif self.peek('u'):
                typ = 'union'
            else:
                raise ValueError(self.rest())
            name, _ = self.__Label(), self.expect(':')
            return self.ForwardDecl(typ, name)

        if last == '@':
            if self.peek('s'):
                kind = 'struct'
            else:
                raise ValueError(self.rest())
            size, _, typ = self.__Number(), self.expect(';'), self.__Type()
            return self.SizeOf(size, typ)

        if last == 'e':
            entries = []
            while not self.peek(';'):
                name, _ = self.__Label(), self.expect(':')
                value, _ = self.__Number(), self.expect(',')
                entries.append(self.Entry(name, value))
            return self.EnumType(entries)

        self.unread()

        return self.__Number()

    def __TypeDecl(self):
        ref = self.__Type()
        if self.peek('='):
            if isinstance(ref, int):
                self.addType(ref, self.__TypeDecl())
            elif isinstance(ref, self.Pointer):
                self.addType(ref.type, self.__TypeDecl())
            else:
                raise RuntimeError(type(ref), self.rest())
        return ref

    def __Info(self):
        name, _ = self.__Label(), self.expect(':')

        last = self.read()

        if last == 't' or last == 'T':
            return self.__TypeDecl()
        if last == 'G':
            return self.Variable(name, ['global'], self.__TypeDecl())
        if last == 'S':
            return self.Variable(name, ['local', 'file'], self.__TypeDecl())
        if last == 'V':
            return self.Variable(name, ['local', 'scope'], self.__TypeDecl())
        if last == 'f':
            return self.Function(name, ['local'], self.__TypeDecl())
        if last == 'F':
            return self.Function(name, ['global'], self.__TypeDecl())
        if last == 'r':
            return self.Register(name, self.__TypeDecl())
        if last == 'p':
            return self.Parameter(name, ['stack'], self.__TypeDecl())
        if last == 'P':
            return self.Parameter(name, ['register'], self.__TypeDecl())

        self.unread()

        return self.__TypeDecl()

    def get(self):
        si = self.__Info()
        if self._pos < len(self._data):
            raise ValueError(self.rest())
        self._data = ''
        self._pos = 0
        return si

    def feed(self, s):
        if s[-1] == '\\':
            self._data += s[:-1]
            return False
        self._data += s
        return True

    def __call__(self, s):
        self._data = s
        self._pos = 0
        return self.get()


class Symbol():
    def __init__(self, address=0, name=''):
        self.address = address
        self.name = name

    def __lt__(self, other):
        if self.address == other.address:
            return self.name < other.name
        return self.address < other.address

    def __str__(self):
        return '%08X: %s' % (self.address, self.name)


class SourceLine():
    def __init__(self, address=0, path=None, line=0, symbol=None):
        self.address = address
        self.path = path
        self.line = line
        self.symbol = symbol

    @property
    def name(self):
        return self.symbol.name

    @property
    def offset(self):
        return self.address - self.symbol.address

    @name.setter
    def name(self, new_name):
        self.symbol.name = new_name

    def __lt__(self, other):
        if self.address == other.address:
            return self.name < other.name
        return self.address < other.address

    def __str__(self):
        s = '%08X' % self.address
        if self.offset == 0:
            s += ' at <%s>' % self.name
        else:
            s += ' at <%s+%d>' % (self.name, self.offset)
        if self.path:
            s += ' in "%s:%d"' % (self.path, self.line)
        return s


class SourceFile():
    def __init__(self, filename):
        self.filename = filename
        self.typemap = {}
        self.parser = StabInfoParser(self.typemap)

    def __str__(self):
        return self.filename


class Section():
    def __init__(self, h, start=0, size=0):
        self.hunk = h
        self.start = start
        self.size = size
        self.symbols = []
        self.lines = []

    @property
    def end(self):
        return self.start + self.size

    def relocate(self, start, size):
        if self.size != size:
            print(self.size, 'vs.', size)
            return False
        diff = start - self.start
        for s in self.symbols:
            s.address += diff
        for l in self.lines:
            l.address += diff
        self.start = start
        return True

    def cleanup(self, extra_lines):
        # remove multiple symbol definitions for the same address
        # we take symbol name without '_' prefix
        symbols = sorted(self.symbols)
        new_symbols = []
        for i, s in enumerate(symbols):
            if i + 1 < len(symbols):
                sn = symbols[i + 1]
                if s.address == sn.address:
                    if sn.name == '_' + s.name:
                        sn.name = s.name
                    continue
            new_symbols.append(s)
        self.symbols = new_symbols

        # common symbols have their source + line information,
        # but must be matched with actual definitions in DATA and BSS sections
        for el in extra_lines:
            for s in self.symbols:
                if s.name == el.name or s.name[1:] == el.name:
                    s.name = el.name
                    sl = SourceLine(s.address, el.path, el.line, s)
                    self.lines.append(sl)
        self.lines = sorted(self.lines)

    def ask_address(self, addr):
        if self.has_address(addr):
            symbols = [SourceLine(address=s.address, symbol=s)
                       for s in self.symbols]
            lines = filter(lambda sl: sl.address <= addr, self.lines + symbols)
            return max(lines, key=lambda e: e.address)

    def ask_symbol(self, name):
        for s in self.symbols:
            if s.name == name:
                return s.address

    def ask_source_line(self, path, line):
        for sl in self.lines:
            if sl.path.endswith(path) and sl.line >= line:
                return sl.address

    def has_address(self, addr):
        return self.start <= addr and addr < self.end

    def dump(self):
        print('%s [%08X - %08X]:' % (self.hunk.type, self.start, self.end))
        print('  SYMBOLS:')
        for s in self.symbols:
            print('    ' + str(s))
        print('  LINES:')
        for l in self.lines:
            print('    ' + str(l))


Scope = namedtuple('Scope', 'begin end values')


class Function():
    def __init__(self):
        self.symbol = Symbol()

        self._scopes = [Scope(0, 0, {})]
        self._begin = None
        self._end = None

    def enterScope(self, addr):
        self._scopes.append(Scope(addr, 0, {}))

    def leaveScope(self, addr):
        vardict = {}
        for scope in reversed(self._scopes):
            for n, v in scope.values.items():
                if n in vardict:
                    continue
                vardict[n] = v
        s = self._scopes.pop()
        return s._replace(end=addr, values=vardict)

    def add(self, n, v):
        self._scopes[-1].values[n] = v


class DebugInfo():
    stab_to_section = {'GSYM': 'COMMON', 'STSYM': 'DATA', 'LCSYM': 'BSS'}

    def __init__(self):
        self.sections = []
        self.files = []

    def relocate(self, segments):
        if len(self.sections) != len(segments):
            return False
        for sec, seg in zip(self.sections, segments):
            if not sec.relocate(seg.start, seg.size):
                return False
        return True

    def dump(self):
        for section in self.sections:
            section.dump()

    def ask_address(self, addr):
        for section in self.sections:
            line = section.ask_address(addr)
            if line:
                return line

    def ask_variables(self, addr):
        pass

    def ask_symbol(self, name):
        for section in self.sections:
            addr = section.ask_symbol(name)
            if addr:
                return addr

    def ask_source_line(self, where):
        path, line = '', 0

        try:
            path, line = where.split(':')
            line = int(line)
        except ValueError:
            return

        for section in self.sections:
            addr = section.ask_source_line(path, line)
            if addr:
                return addr

    def fromFile(self, executable):
        common = Section(None)
        last = {'CODE': None, 'DATA': None, 'BSS': None, 'COMMON': common}
        start = 0
        size = 0

        for h in hunk.ReadFile(executable):

            if h.type in ['HUNK_CODE', 'HUNK_DATA', 'HUNK_BSS']:
                start += size
                size = h.size
                sec = Section(h, start, size)
                last[h.type[5:]] = sec
                self.sections.append(sec)

            elif h.type is 'HUNK_SYMBOL':
                for s in h.symbols:
                    address, name = s.refs + start, s.name
                    if name[0] == '_':
                        name = name[1:]
                    self.sections[-1].symbols.append(Symbol(address, name))

            elif h.type is 'HUNK_DEBUG':
                stabs = h.data

                # h.dump()

                func = Function()
                dirname = ''
                filename = ''
                source = None

                for st in stabs:
                    # N_SO: path and name of source file
                    # N_SOL: name of include file
                    if st.type in ['SO', 'SOL']:
                        if st.str[-1] == '/':
                            dirname = st.str
                        else:
                            if st.str[0] == '/':
                                filename = st.str
                            else:
                                filename = dirname + st.str
                            if st.type == 'SO':
                                source = SourceFile(filename)

                    # N_DATA: data symbol
                    # N_BSS: BSS symbol
                    elif st.type in ['DATA', 'BSS']:
                        s = Symbol(st.value, st.str)
                        last[st.type].symbols.append(s)

                    # N_GSYM: global symbol
                    # N_STSYM: data segment file-scope variable
                    # N_LCSYM: BSS segment file-scope variable
                    elif st.type in ['GSYM', 'STSYM', 'LCSYM']:
                        if source.parser.feed(st.str):
                            si = source.parser.get()
                            s = Symbol(st.value, si.name)
                            sl = SourceLine(st.value, source, st.desc, s)
                            sec = last[DebugInfo.stab_to_section[st.type]]
                            sec.symbols.append(s)
                            sec.lines.append(sl)

                    # N_LSYM: stack variable or type
                    elif st.type in ['LSYM']:
                        if source.parser.feed(st.str):
                            si = source.parser.get()

                    # N_SLINE: line number in text segment
                    elif st.type in ['SLINE']:
                        # address, path, line, symbol
                        sl = SourceLine(st.value, source, st.desc, func.symbol)
                        last['CODE'].lines.append(sl)

                    # N_FUN: function name or text segment variable
                    elif st.type in ['FUN']:
                        si = source.parser(st.str)
                        func.symbol.address = st.value
                        func.symbol.name = si.name
                        last['CODE'].symbols.append(func.symbol)
                        func = Function()

                    elif st.type in ['TEXT']:
                        pass

                    elif st.type in ['LBRAC']:
                        func.enterScope(st.value)

                    elif st.type in ['RBRAC']:
                        varlst = func.leaveScope(st.value)
                        # print(varlst)

                    # N_RSYM: register variable
                    elif st.type in ['RSYM']:
                        if source.parser.feed(st.str):
                            si = source.parser.get()
                            # print('ParamReg(line=%d name="%s" num=%d type=%d)'
                            #       % (st.desc, si.name, st.value, si.type))
                            func.add(si.name, si.type)

                    # N_PSYM: parameter variable
                    elif st.type in ['PSYM']:
                        if source.parser.feed(st.str):
                            si = source.parser.get()
                            # print('ParamStk(line=%d name="%s" off=%d type=%d)'
                            #       % (st.desc, si.name, st.value, si.type))
                            func.add(si.name, si.type)

                    else:
                        raise ValueError('%s: not handled!', st.type)

        for section in self.sections:
            section.cleanup(common.lines)
