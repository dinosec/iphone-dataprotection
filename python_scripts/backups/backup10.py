import os
import re
import sqlite3

def decrypt_backup10(backup_path, output_path):
    connection = sqlite3.connect(backup_path + "/Manifest.db")
    try:
        connection.row_factory = sqlite3.Row
        cursor = connection.cursor()

        for record in cursor.execute("SELECT fileID, domain, relativePath, flags, file FROM Files"):
            extract_file(backup_path, output_path, record)
    except:
        connection.close()

def extract_file(backup_path, output_path, record):
    # adjust output file name
    #if record.is_symbolic_link():
    #    out_file = record.target
    #else:
    out_file = record["relativePath"]

    # read backup file
    try:
        fileID = record["fileID"]
        filename = os.path.join(backup_path, fileID[:2], fileID)
        #print filename
        f1 = file(filename, "rb")
    except(IOError):
        print "WARNING: File %s (%s) has not been found" % (filename, record["relativePath"])
        return

    # write output file
    out_file = re.sub(r'[:|*<>?"]', "_", out_file)
    output_path = os.path.join(output_path, record["domain"], out_file)

    ensure_dir_exists(output_path)

    print("Writing %s" % output_path)
    f2 = file(output_path, 'wb')

    while True:
        data = f1.read(8192)
        if not data:
            break
        f2.write(data)

    f1.close()
    f2.close()

def ensure_dir_exists(filename):
    if not os.path.exists(os.path.dirname(filename)):
        try:
            os.makedirs(os.path.dirname(filename))
        except OSError as exc: # Guard against race condition
            if exc.errno != errno.EEXIST:
                raise
