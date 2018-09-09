# Falkervisor (brownie)

This is one of the first versions of falkervisor. It was used to find bugs in Chrome sandbox, Windows Defender, Word (RTF), and probably some other random crap between 2014-2015. Since I didn't use version control I'm probably missing pieces, but this actually builds and should run on any AMD fam15h machine. It should be able to boot up single-core OSes right off IDE based disk, and take snapshots via proprietary falktp which I don't have the server for anymore, so you'd have to reverse it. You also need an Intel x540 for this to run.

It was quickly dropped in favor of C once I became more sane. It is the foundation of most of the concepts used in my modern version of falkervisor, which is now written in Rust.

Fun fact, this is still the version I use for snapshots as it's my only hypervisor with IOMMU support!

There's some cool historical shit in here:
- It's all assembly, cause I was/am dumb
- It has NUMA support
- It has CoW support so minimal memory is used to fuzz
- It quickly restores to a snapshot by walking dirty bits
- It has IOMMU support but uses hardcoded e820 tables for guests xD
- It has many different forms of support for reading/writing guest memory
- It can run live OSes under it, or run from a snapshot downloaded from network
- It uses many different types of coverage
- It builds instantly, just run `nmake` or `make`

I'd be impressed if someone got this to run and take a snapshot. It has all the code here, but some tweaks would need to be made for your specific hardware.
