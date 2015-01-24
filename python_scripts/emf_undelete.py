#!/usr/bin/python
import os
import sys
from hfs.emf import EMFVolume
from hfs.journal import do_emf_carving
from util.bdev import FileBlockDevice

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print "Usage: emf_undelete.py disk_image.bin"
        sys.exit(0)
    filename = sys.argv[1]
    volume = EMFVolume(FileBlockDevice(filename), None)
    dirname = os.path.dirname(filename)
    if dirname == "":
        dirname = "."
    outdir = dirname + "/" + volume.volumeID().encode("hex") + "_" + os.path.basename(filename)
    carveokdir = outdir + "/undelete/"
    carvenokdir = outdir + "/junk/"
    try:
        os.makedirs(carveokdir)
        os.makedirs(carvenokdir)
    except:
        pass
    
    do_emf_carving(volume, carveokdir, carvenokdir)
