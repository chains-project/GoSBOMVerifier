import re
import struct

def find_elf_section(data, section_name):
    
    if len(data) < 64 or data[:4] != b'\x7fELF':
        return None, None
    if data[4] != 2:  # EI_CLASS != ELFCLASS64
        return None, None
    endian = '<' if data[5] == 1 else '>'

    e_shoff = struct.unpack(endian + 'Q', data[40:48])[0]
    e_shentsize = struct.unpack(endian + 'H', data[58:60])[0]
    e_shnum = struct.unpack(endian + 'H', data[60:62])[0]
    e_shstrndx = struct.unpack(endian + 'H', data[62:64])[0]

    if e_shoff == 0 or e_shnum == 0 or e_shstrndx >= e_shnum:
        return None, None

    shstr_hdr = e_shoff + e_shstrndx * e_shentsize
    shstr_offset = struct.unpack(endian + 'Q', data[shstr_hdr + 24:shstr_hdr + 32])[0]
    shstr_size = struct.unpack(endian + 'Q', data[shstr_hdr + 32:shstr_hdr + 40])[0]
    shstrtab = data[shstr_offset:shstr_offset + shstr_size]

    target = section_name.encode('ascii')
    for i in range(e_shnum):
        sh_off = e_shoff + i * e_shentsize
        sh_name_idx = struct.unpack(endian + 'I', data[sh_off:sh_off + 4])[0]
        name = shstrtab[sh_name_idx:].split(b'\x00', 1)[0]
        if name == target:
            sec_off = struct.unpack(endian + 'Q', data[sh_off + 24:sh_off + 32])[0]
            sec_size = struct.unpack(endian + 'Q', data[sh_off + 32:sh_off + 40])[0]
            return sec_off, sec_size

    return None, None

def extract_symtab_bytes(data):
    
    symtab_off, symtab_size = find_elf_section(data, '.symtab')
    strtab_off, strtab_size = find_elf_section(data, '.strtab')

    chunks = []
    if symtab_off is not None and symtab_size:
        chunks.append(data[symtab_off:symtab_off + symtab_size])
    if strtab_off is not None and strtab_size:
        chunks.append(data[strtab_off:strtab_off + strtab_size])
    return b''.join(chunks)

def extract_gopclntab_bytes(data):
    
    for section in ('.gopclntab', '__gopclntab', '.go.pclntab'):
        off, size = find_elf_section(data, section)
        if off is not None and size:
            return data[off:off + size]

    for magic in (b'\xfb\xff\xff\xff\x00\x00',
                  b'\xfa\xff\xff\xff\x00\x00',
                  b'\xf0\xff\xff\xff\x00\x00',
                  b'\xf1\xff\xff\xff\x00\x00'):
        idx = data.find(magic)
        if idx >= 0:
            return data[idx:]
    return b''

def extract_go_version(data):
    match = re.search(rb'(go1\.\d+(?:\.\d+)?)', data)
    if match:
        return match.group(1).decode('ascii')
    return None

def clean_module_string(s):
    for prefix in ('eq.', 'itab.', 'hash.', 'type.', 'type:.'):
        if s.startswith(prefix):
            s = s[len(prefix):]
    return s

def extract_function_packages(data):
    pattern = re.compile(
        rb'(?:eq\.|itab\.|hash\.|type[.:])?' +
        rb'((?:[a-zA-Z][a-zA-Z0-9_.-]*\.(?:com|org|io|in)/[a-zA-Z0-9/_%.+-]+)\.[A-Z_a-z]\w*)',
        re.ASCII
    )

    packages = set()
    for m in pattern.findall(data):
        s = m.decode('ascii', errors='ignore')
        s = clean_module_string(s)
        # Decode URL-encoded dots (gopkg.in/yaml%2ev3 -> gopkg.in/yaml.v3)
        s = s.replace('%2e', '.')
        if '/' in s:
            last_slash = s.rfind('/')
            after_slash = s[last_slash + 1:]
            dot_pos = after_slash.find('.')
            if dot_pos >= 0:
                pkg = s[:last_slash + 1 + dot_pos]
                # gopkg.in/yaml.v3.Marshal -> gopkg.in/yaml.v3
                if pkg.startswith('gopkg.in/'):
                    rest = after_slash[dot_pos:]  # e.g. ".v3.Marshal"
                    vn_match = re.match(r'\.(v\d+)', rest)
                    if vn_match:
                        pkg = pkg + '.' + vn_match.group(1)
                packages.add(pkg)

    return sorted(packages)

def extract_function_packages_from_symtab(data):
    
    section_bytes = extract_symtab_bytes(data)
    if not section_bytes:
        return []
    return extract_function_packages(section_bytes)

def extract_function_packages_from_gopclntab(data):
   
    section_bytes = extract_gopclntab_bytes(data)
    if not section_bytes:
        return []
    return extract_function_packages(section_bytes)

def packages_to_modules(packages):
    modules = set()
    for pkg in packages:
        parts = pkg.split('/')
        if len(parts) < 2:
            continue

        top = parts[0]

        if top == 'gopkg.in':
            mod = '/'.join(parts[:2])
        elif len(parts) >= 3:
            mod = '/'.join(parts[:3])
        else:
            mod = '/'.join(parts[:2])

        # Check for versioned modules
        next_idx = len(mod.split('/'))
        if next_idx < len(parts) and re.match(r'^v\d+$', parts[next_idx]):
            mod = mod + '/' + parts[next_idx]

        modules.add(mod)

    return sorted(modules)

def is_stdlib_package(pkg):
    top = pkg.split("/")[0]
    if "." not in top:
        return True
    return False

def verify_sbom(detected_modules, sbom_libs):
   
    def normalize(name):
        n = name.strip().rstrip('/').lower()
        n = n.replace('%2e', '.')
        n = n.replace('.', '/').replace('_', '/')
        while '//' in n:
            n = n.replace('//', '/')
        return n

    detected_norm = {normalize(m): m for m in detected_modules}
    sbom_norm = {normalize(lib): lib for lib in sbom_libs}

    confirmed = []
    not_detected = []
    unlisted = []

    for norm_name, orig_name in sorted(sbom_norm.items()):
        if norm_name in detected_norm:
            confirmed.append(orig_name)
        else:
            found = False
            for det_norm in detected_norm:
                if det_norm.startswith(norm_name) or norm_name.startswith(det_norm):
                    confirmed.append(orig_name)
                    found = True
                    break
            if not found:
                not_detected.append(orig_name)

    for norm_name, orig_name in sorted(detected_norm.items()):
        is_in_sbom = False
        for sbom_n in sbom_norm:
            if norm_name.startswith(sbom_n) or sbom_n.startswith(norm_name):
                is_in_sbom = True
                break
        if not is_in_sbom:
            unlisted.append(orig_name)

    return confirmed, not_detected, unlisted
