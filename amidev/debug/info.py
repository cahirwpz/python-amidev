import os
from amidev.binfmt import hunk


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
    def __init__(self, address=0, path='', line=0, symbol=None):
        self.address = address
        self.path = path
        self.line = line
        self.symbol = symbol

    @property
    def name(self):
        return self.symbol.name

    @name.setter
    def name(self, new_name):
        self.symbol.name = new_name

    def __lt__(self, other):
        if self.address == other.address:
            return self.name < other.name
        return self.address < other.address

    def __str__(self):
        return '%08X: %s %s:%d' % (self.address, self.name, self.path, self.line)


class Section():
    def __init__(self, name, start=0, size=0):
        self.name = name
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
            candidate = self.lines[0]
            l = [e for e in self.lines if e.address <= addr] + \
                [e for e in self.symbols if e.address <= addr]
            return max(l, key=lambda e: e.address)

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
        print('%s [%08X - %08X]:' % (self.name, self.start, self.end))
        print('  SYMBOLS:')
        for s in self.symbols:
            print('    ' + str(s))
        print('  LINES:')
        for l in self.lines:
            print('    ' + str(l))


class DebugInfo():
    stab_to_section = {'GSYM': 'COMMON', 'STSYM': 'DATA', 'LCSYM': 'BSS'}
    hunk_to_section = {'HUNK_CODE': 'TEXT',
                       'HUNK_DATA': 'DATA',
                       'HUNK_BSS': 'BSS'}

    def __init__(self, sections):
        self.sections = sections

    def relocate(self, name, start, size):
        return self.sections[name].relocate(start, size)

    def dump(self):
        for name in ['TEXT', 'DATA', 'BSS']:
            self.sections[name].dump()

    def ask_address(self, addr):
        for section in self.sections.values():
            l = section.ask_address(addr)
            if l:
                return l

    def ask_symbol(self, name):
        for section in self.sections.values():
            a = section.ask_symbol(name)
            if a:
                return a

    def ask_source_line(self, where):
        path, line = '', 0

        try:
            path, line = where.split(':')
            line = int(line)
        except ValueError:
            return

        for section in self.sections.values():
            a = section.ask_source_line(path, line)
            if a:
                return a

    @classmethod
    def fromFile(cls, executable):
        sections = {'COMMON': Section('COMMON')}
        current = None
        start = 0
        size = 0

        for h in hunk.ReadFile(executable):
            # h.dump()

            if h.type in ['HUNK_CODE', 'HUNK_DATA', 'HUNK_BSS']:
                start += size
                name = cls.hunk_to_section[h.type]
                size = h.size
                current = Section(name, start, size)
                sections[name] = current

            elif h.type is 'HUNK_SYMBOL':
                for s in h.symbols:
                    address, name = s.refs + start, s.name
                    if name[0] == '_':
                        name = name[1:]
                    current.symbols.append(Symbol(address, name))

            elif h.type is 'HUNK_DEBUG':
                stabs, strings = h.data

                func = Symbol()
                path = ''
                source = ''

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
                        sections[st.type_str].symbols.append(s)

                    # N_GSYM: global symbol
                    # N_STSYM: data segment file-scope variable
                    # N_LCSYM: BSS segment file-scope variable
                    if st.type_str in ['GSYM', 'STSYM', 'LCSYM']:
                        s = Symbol(st.value, stabsym.split(':')[0])
                        sl = SourceLine(st.value, source, st.desc, s)
                        sec = sections[cls.stab_to_section[st.type_str]]
                        sec.symbols.append(s)
                        sec.lines.append(sl)

                    # N_SLINE: line number in text segment
                    if st.type_str in ['SLINE']:
                        sl = SourceLine(st.value, source, st.desc, func)
                        sections['TEXT'].lines.append(sl)

                    # N_FUN: function name or text segment variable
                    if st.type_str in ['FUN']:
                        func.address = st.value
                        func.name = stabsym.split(':')[0]
                        sections['TEXT'].symbols.append(func)
                        func = Symbol()

        for name in ['TEXT', 'DATA', 'BSS']:
            sections[name].cleanup(sections['COMMON'].lines)
        del sections['COMMON']
        return cls(sections)


