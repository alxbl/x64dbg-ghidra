# Import an x64dbg database file to Ghidra's Program DB
#
# There is no way to extract an lz4 database from Ghidra currently so it is
# necessary to manually extract the .dd32 or .dd64 database manually first.
#
# This can be done (on Linux) with the following command:
#
#     lz4  -d path/to/db.dd32 out.json
#
import json

def main():
    try:
        PATH = str(askFile("Select Database file", "Import"))
    except:
        printerr('[-] Import cancelled.')
        return

    PROG = str(currentProgram.getName())
    BASE = currentProgram.getAddressMap().getImageBase()

    with open(PATH, 'rb') as f: db = json.load(f)
    comments  = db['comments']
    labels    = db['labels']
    bookmarks = db['bookmarks']
    functions = db['functions']


    # Comments -----------------------------------------------------------------
    print('[*] Parsing %d comments' % (len(comments)))
    imported = 0
    for c in filter(lambda x: x['module'] == PROG, comments):
        module, rva, text = c['module'], int(c['address'], 16), c['text']
        if module != PROG: continue # Not for this image => Skip.

        address = BASE.add(rva)
        cur = getEOLComment(address)
        if cur is None: cur = ''
        if text in cur: continue # Already imported => Skip.

        comment = text if not cur else '\n'.join([text, cur])
        setEOLComment(address, comment)
        imported += 1
    print('[+] Imported %d new comments' % (imported))

    # Bookmarks ----------------------------------------------------------------
    print('[*] Parsing %d bookmarks' % (len(bookmarks)))
    imported = 0
    for e in bookmarks:
        module, rva = e['module'], int(e['address'], 16)
        address = BASE.add(rva)
        b = list(getBookmarks(address))

        # Bookmarks do not have metadata in x64dbg, so there is no point in
        # re-importing a bookmark if the address is bookmarked at least once.
        if len(b): continue

        createBookmark(address, 'x64dbg', 'Imported: ' + PATH)
        imported += 1
    print('[+] Imported %d new bookmarks' % (imported))

main()
