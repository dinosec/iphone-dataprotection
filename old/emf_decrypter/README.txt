DEPRECATED: use the python version instead

Decrypts files data forks in raw iOS 4 disk images.
Reads encryption keys from plist file named after the volume ID.
The plist file must have at least the EMF and DKey fields set.
For now the tool decrypts the data forks but does not mark the files as 
"decrypted" : running it twice on the same image will produce garbage. 
Interrupting the process will also leave the image "half decrypted".

Uses planetbeing/dev team HFS implementation
https://github.com/planetbeing/xpwn

Only builds on Mac OS X, requires CoreFoundation for plist access.