import os
import re
from collections import namedtuple

from amidev.binfmt import hunk


Segment = namedtuple('Segment', 'start size')


class StabInfoParser():
    Field = namedtuple('Field', 'name type offset size')
    StructType = namedtuple('StructType', 'size fields')
    UnionType = namedtuple('UnionType', 'size fields')
    MachType = namedtuple('MachType', 'id min max')
    AliasType = namedtuple('AliasType', 'id')
    ArrayType = namedtuple('ArrayType', 'i j k type')
    FunctionType = namedtuple('FunctionType', 'id')
    PointerType = namedtuple('PointerType', 'id')
    TypeDecl = namedtuple('TypeDecl', 'id')
    ForwardDecl = namedtuple('ForwardDecl', 'type name')
    Info = namedtuple('Info', 'symbol info')

    def __init__(self):
        self._data = ''
        self._pos = 0

        self._typemap = [
            ('ar', self.__ArrayType),
            ('t', self.__TypeDecl),
            ('T', self.__TypeDecl),
            ('r', self.__MachType),
            ('s', self.__StructType),
            ('u', self.__UnionType),
            ('f', self.__FunctionType),
            ('*', self.__PointerType),
            ('x', self.__ForwardDecl)]

    def expect(self, string):
        if not self._data.startswith(string, self._pos):
            raise ValueError(self.rest())
        self._pos += len(string)

    def consume(self, regex):
        m = regex.match(self._data, self._pos)
        if not m:
            raise ValueError(self.rest())
        self._pos += len(m.group(0))
        return m.group(0)

    def peek(self, string):
        if not self._data.startswith(string, self._pos):
            return False
        self._pos += len(string)
        return True

    TLabel = re.compile(r'[A-Za-z0-9_ ]+')
    TNumber = re.compile(r'-?[0-9]+')

    def rest(self):
        return self._data[self._pos:]

    def __Label(self):
        return self.consume(self.TLabel)

    def __Number(self):
        number = self.consume(self.TNumber)
        if number[0] == '0':
            return int(number, 8)
        return int(number)

    def __Field(self):
        name = self.__Label(), self.expect(':')
        typedef = self.__TypeDef(), self.expect(',')
        offset = self.__Number(), self.expect(',')
        size = self.__Number(), self.expect(';')
        return self.Field(name, typedef, offset, size)

    def __ArrayType(self):
        i, _ = self.__Number(), self.expect(';')
        j, _ = self.__Number(), self.expect(';')
        k, _ = self.__Number(), self.expect(';')
        typ = self.__Type()
        return self.ArrayType(i, j, k, typ)

    def __TypeDecl(self):
        return self.TypeDecl(self.__Number())

    def __MachType(self):
        _id, _ = self.__Number(), self.expect(';')
        _min, _ = self.__Number(), self.expect(';')
        _max, _ = self.__Number(), self.expect(';')
        if _min > 0:
            _min = -_min
        return self.MachType(_id, _min, _max)

    def __StructType(self):
        size = self.__Number()
        fields = []
        while not self.peek(';'):
            fields.append(self.__Field())
        return self.StructType(size, fields)

    def __UnionType(self):
        size = self.__Number()
        fields = []
        while not self.peek(';'):
            fields.append(self.__Field())
        return self.UnionType(size, fields)

    def __FunctionType(self):
        return self.FunctionType(self.__Number())

    def __PointerType(self):
        return self.PointerType(self.__Number())

    def __ForwardDecl(self):
        typ = ''
        if self.peek('s'):
            typ = 'struct'
        elif self.peek('u'):
            typ = 'union'
        else:
            raise ValueError(self.rest())
        name, _ = self.__Label(), self.expect(':')
        return self.ForwardDecl(typ, name)

    def __Type(self):
        for tid, func in self._typemap:
            if self.peek(tid):
                return func()
        return self.AliasType(self.__Number())

    def __TypeDef(self):
        typelist = [self.__Type()]
        while self.peek('='):
            typelist.append(self.__Type())
        return typelist

    def __Info(self):
        symbol, _, info = self.__Label(), self.expect(':'), self.__TypeDef()
        return self.Info(symbol, info)

    def __call__(self, s):
        self._data = s
        self._pos = 0
        return self.__Info()


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


class DebugInfo():
    stab_to_section = {'GSYM': 'COMMON', 'STSYM': 'DATA', 'LCSYM': 'BSS'}

    def __init__(self, sections):
        self.sections = sections

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

    @classmethod
    def fromFile(cls, executable):
        sections = []
        common = Section(None)
        last = {'CODE': None, 'DATA': None, 'BSS': None, 'COMMON': common}
        start = 0
        size = 0

        parser = StabInfoParser()

        for h in hunk.ReadFile(executable):
            # h.dump()

            if h.type in ['HUNK_CODE', 'HUNK_DATA', 'HUNK_BSS']:
                start += size
                size = h.size
                sec = Section(h, start, size)
                last[h.type[5:]] = sec
                sections.append(sec)

            elif h.type is 'HUNK_SYMBOL':
                for s in h.symbols:
                    address, name = s.refs + start, s.name
                    if name[0] == '_':
                        name = name[1:]
                    sections[-1].symbols.append(Symbol(address, name))

            elif h.type is 'HUNK_DEBUG':
                stabs, strings = h.data

                func = Symbol()
                path = ''
                source = ''
                lsym = ''

                for st in stabs:
                    stabsym = st.symbol(strings)

                    # N_SO: path and name of source file
                    # N_SOL: name of include file
                    if st.type_str in ['SO', 'SOL']:
                        if stabsym.endswith('/'):
                            path = stabsym
                        else:
                            if stabsym.startswith('/'):
                                source = stabsym
                            else:
                                source = os.path.join(path, stabsym)

                    # N_DATA: data symbol
                    # N_BSS: BSS symbol
                    if st.type_str in ['DATA', 'BSS']:
                        s = Symbol(st.value, stabsym)
                        last[st.type_str].symbols.append(s)

                    # N_GSYM: global symbol
                    # N_STSYM: data segment file-scope variable
                    # N_LCSYM: BSS segment file-scope variable
                    if st.type_str in ['GSYM', 'STSYM', 'LCSYM']:
                        s = Symbol(st.value, stabsym.split(':')[0])
                        sl = SourceLine(st.value, source, st.desc, s)
                        sec = last[cls.stab_to_section[st.type_str]]
                        sec.symbols.append(s)
                        sec.lines.append(sl)

                    # N_LSYM: stack variable or type
                    if st.type_str in ['LSYM']:
                        if stabsym.endswith('\\'):
                            lsym += stabsym[:-1]
                        else:
                            lsym += stabsym
                            parser(lsym)
                            lsym = ''

                    # N_SLINE: line number in text segment
                    if st.type_str in ['SLINE']:
                        sl = SourceLine(st.value, source, st.desc, func)
                        last['CODE'].lines.append(sl)

                    # N_FUN: function name or text segment variable
                    if st.type_str in ['FUN']:
                        func.address = st.value
                        func.name = stabsym.split(':')[0]
                        last['CODE'].symbols.append(func)
                        func = Symbol()

        for section in sections:
            section.cleanup(common.lines)

        return cls(sections)
