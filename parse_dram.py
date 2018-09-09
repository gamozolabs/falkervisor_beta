datas = [[3, 0x10270000, 0, 0],
        [0x10280003, 0x20270001, 0, 0],
        [0x20280003, 0x30270002, 0, 0],
        [0x30280003, 0x40260003, 0, 0]]

for data in datas:
    dram_base = ((data[2] & 0xff) << 40) | ((data[0] & 0xffff0000) << (24 - 16))
    intlv_en  = data[0] & (3 << 8)
    we        = data[0] & (1 << 1)
    re        = data[0] & (1 << 0)

    dram_limit = ((data[3] & 0xff) << 40) | ((data[1] & 0xffff0000) << (24 - 16)) | 0xFFFFFF
    intlv_sel  = data[1] & (3 << 8)
    dst_node   = data[1] & 3

    print   "DRAM Base:      %.16x\n" \
            "DRAM Limit:     %.16x\n" \
            "Interleave En:  %d\n" \
            "Write En:       %d\n" \
            "Read En:        %d\n" \
            "Interleave Sel: %d\n" \
            "Dest node:      %d" % (dram_base, dram_limit, intlv_en, we, re, intlv_sel, dst_node)
    print

