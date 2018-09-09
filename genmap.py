mmio_ranges = [
        [0xD9000000, 0xDFFFFFFF],
		[0xD6000000, 0xD8FFFFFF],
        [0xE0000000, 0xEFFFFFFF],
        [0x000A0000, 0x000BFFFF],
        [0xF0000000, 0xFFFFFFFF],
        [0x00700000, 0x00E0FFFF]]

def is_mmio(addr):
    for ra in mmio_ranges:
        if addr >= ra[0] and (addr + 4095) <= ra[1]:
            return True

    return False

e820_map = [
        [0x0, 0x9e400, 0x1],
        [0x9e400, 0x1c00, 0x2],
        [0xe8000, 0x18000, 0x2],
        [0x100000, 0xcfd60000, 0x1],
		]

def e820(addr):
    for ra in e820_map:
        if addr >= ra[0] and (addr + 4096) < (ra[0] + ra[1]):
            return ra[2]

    return 2

da_map = []
start = 0
chain = 0

for addr in range(0, 1024 * 1024 * 1024 * 256, 4096):
    if is_mmio(addr) == False and e820(addr) == 1:
        if chain == 0:
            start = addr

        chain = 1
    else:
        da_len = addr - start
        if chain:
            da_map.append([start, da_len])

        chain = 0

    #print is_mmio(addr), e820(addr)

i = 1
for map in da_map:
    print "\t dq 0x%.8x, 0x%.8x, 0x1, 0x%x" % (map[0], map[1], i)
    i += 1

