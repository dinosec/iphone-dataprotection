#HAX

d=open("redsn0w_win_0.9.9b4/redsn0w.exe", "rb").read()

i = d.find("<key>IV</key>")
i = d.rfind("<?xml",0,i)
j = d.find("</plist>", i)

assert i != -1
assert j != -1

open("Keys.plist", "wb").write(d[i:j+8])
