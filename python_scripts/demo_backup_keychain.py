#!/usr/bin/env python

import sys, os
from PyQt4 import QtGui, QtCore
from backups.backup4 import MBDB
from keychain.keychain4 import Keychain4
from util.bplist import BPlistReader
from keystore.keybag import Keybag
from util import readPlist

class KeychainTreeWidget(QtGui.QTreeWidget):
    def __init__(self, parent=None):
        QtGui.QTreeWidget.__init__(self, parent)

        self.setGeometry(10, 10, 780, 380)
        self.header().hide()
        self.setColumnCount(2)
        
class KeychainTreeWidgetItem(QtGui.QTreeWidgetItem):
    def __init__(self, title):
        QtGui.QTreeWidgetItem.__init__(self, [title])

        fnt = self.font(0)
        fnt.setBold(True)
        self.setFont(0, fnt)
        self.setColors()

    def setText(self, column, title):
        QtGui.QTreeWidgetItem.setText(self, column, title)

    def setColors(self):
        self.setForeground(0, QtGui.QBrush(QtGui.QColor(80, 80, 80)))
        self.setBackground(0, QtGui.QBrush(QtGui.QColor(230, 230, 230)))
        self.setBackground(1, QtGui.QBrush(QtGui.QColor(230, 230, 230)))

class LockedKeychainTreeWidgetItem(KeychainTreeWidgetItem):
    def setColors(self):
        self.setForeground(0, QtGui.QBrush(QtGui.QColor(255, 80, 80)))
        self.setBackground(0, QtGui.QBrush(QtGui.QColor(255, 230, 230)))
        self.setBackground(1, QtGui.QBrush(QtGui.QColor(255, 230, 230)))

class KeychainWindow(QtGui.QWidget):
    def __init__(self, parent=None):
        QtGui.QWidget.__init__(self, parent)

        self.setGeometry(100, 100, 800, 400)
        self.setWindowTitle('Keychain Explorer')

        self.passwordTree = KeychainTreeWidget(parent=self)

    def setGenericPasswords(self, pwds):
        self.genericPasswords = pwds

        self.passwordItems = KeychainTreeWidgetItem('Generic Passwords')

        for pwd in self.genericPasswords:
            if not pwd.has_key('acct'):
                continue
            if len(pwd['acct']) > 0:
                item_title = '%s (%s)' % (pwd['svce'], pwd['acct'])
            else:
                item_title = pwd['svce']

            if pwd['data'] is None:
                item = LockedKeychainTreeWidgetItem(item_title)
            else:
                item = KeychainTreeWidgetItem(item_title)

            item.addChild(QtGui.QTreeWidgetItem(['Service', pwd['svce']]))
            item.addChild(QtGui.QTreeWidgetItem(['Account', pwd['acct']]))
            if pwd['data'] is not None:
                item.addChild(QtGui.QTreeWidgetItem(['Data', pwd['data']]))
            else:
                item.addChild(QtGui.QTreeWidgetItem(['Data', 'N/A']))
            item.addChild(QtGui.QTreeWidgetItem(['Access Group', pwd['agrp']]))

            self.passwordItems.addChild(item)

        self.passwordTree.addTopLevelItem(self.passwordItems)

        self.passwordTree.expandAll()
        self.passwordTree.resizeColumnToContents(0)

    def setInternetPasswords(self, pwds):
        self.internetPasswords = pwds

        self.internetPasswordItems = KeychainTreeWidgetItem('Internet Passwords')

        for pwd in pwds:
            item_title = '%s (%s)' % (pwd['srvr'], pwd['acct'])

            item = KeychainTreeWidgetItem(item_title)

            item.addChild(QtGui.QTreeWidgetItem(['Server', pwd['srvr']]))
            item.addChild(QtGui.QTreeWidgetItem(['Account', pwd['acct']]))
            if pwd['data'] is not None:
                item.addChild(QtGui.QTreeWidgetItem(['Data', pwd['data']]))
            else:
                item.addChild(QtGui.QTreeWidgetItem(['Data', 'N/A']))

            item.addChild(QtGui.QTreeWidgetItem(['Port', str(pwd['port'])]))
            item.addChild(QtGui.QTreeWidgetItem(['Access Group', pwd['agrp']]))

            self.internetPasswordItems.addChild(item)

        self.passwordTree.addTopLevelItem(self.internetPasswordItems)

        self.passwordTree.expandAll()
        self.passwordTree.resizeColumnToContents(0)

def warn(msg):
    print "WARNING: %s" % msg

def getBackupKeyBag(backupfolder, passphrase):
    manifest = readPlist(backupfolder + "/Manifest.plist")

    kb = Keybag(manifest["BackupKeyBag"].data)

    if kb.unlockBackupKeybagWithPasscode(passphrase):
        print "BackupKeyBag unlock OK"
        return kb
    else:
        return None
    
def main():
    app = QtGui.QApplication(sys.argv)
    init_path = "{0:s}/Apple Computer/MobileSync/Backup".format(os.getenv('APPDATA'))
    dirname = QtGui.QFileDialog.getExistingDirectory(None, "Select iTunes backup directory", init_path)
    kb = getBackupKeyBag(dirname, 'pouet')	#XXX: hardcoded password for demo
    if not kb:
        warn("Backup keybag unlock fail : wrong passcode?")
        return
    db = MBDB(dirname)
    db.keybag = kb
    filename, record = db.get_file_by_name("keychain-backup.plist")
    keychain_data = db.read_file(filename, record)
    
    f = file('keychain.tmp', 'wb')
    f.write(keychain_data)
    f.close()

    kc = Keychain4('keychain.tmp', kb)

    pwds = kc.get_passwords()
    inet_pwds = kc.get_inet_passwords()

    qb = KeychainWindow()
    qb.setGenericPasswords(pwds)
    qb.setInternetPasswords(inet_pwds)
    qb.show()

    sys.exit(app.exec_())
    pass

if __name__ == '__main__':
    main()
