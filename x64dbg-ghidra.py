# Import an x64dbg database file to Ghidra's Program DB
#
# There is no way to extract an lz4 database with the Ghidra API currently so
# it is necessary to manually extract the .dd32 or .dd64 database manually
# first.
#
# This can be done (on Linux) with the following command:
#
#     lz4 -d path/to/db.dd32 out.json
#
# Alternatively, you can use x64dbg's Export Database function in the "File"
# menu and import the resulting .dd32 or .dd64 file.
#
# @category x64dbg
#
import json
IMPORTED = ghidra.program.model.symbol.SourceType.IMPORTED
FUNCTION = ghidra.program.model.symbol.SymbolType.FUNCTION

def get(db, section): return db[section] if section in db else []

def import_symbols(labels, functions, base):
    print('[*] Parsing %d symbols' % (len(labels)))
    new_labels = 0
    new_functions = 0
    f = dict(map(lambda f: (int(f['start'], 16), int(f['end'], 16)), functions))
    l = dict(map(lambda l: (int(l['address'], 16), l['text']), labels))

    for rva, text in l.items():
        address = base.add(rva)
        s = getSymbolAt(address)

        # If the symbol already has a name that isn't a built-in Ghidra name, ignore it.
        if s is not None and all(map(lambda x: not s.name.startswith(x), ['LAB_', 'DAT_', 'FUN_', 'PTR_'])): continue

        if rva in f: # It's a function symbol.
            if s and s.getSymbolType() == FUNCTION: s.setName(text, IMPORTED)
            else: createFunction(address, text)
            new_functions += 1
        else: # It's a regular label.
            if s is not None: s.setName(text, IMPORTED)
            else: createLabel(address, text, True, IMPORTED)
            new_labels += 1

    print('[+] Imported %d new symbols (%d functions, %d labels)' % (new_functions + new_labels, new_functions, new_labels))



def main():
    try:
        PATH = str(askFile("Select Database file", "Import"))
    except:
        printerr('[-] Import cancelled.')
        return

    PROG = str(currentProgram.getName())
    BASE = currentProgram.getAddressMap().getImageBase()

    with open(PATH, 'rb') as f: db = json.load(f)
    comments  = get(db, 'comments')
    labels    = get(db, 'labels')
    bookmarks = get(db, 'bookmarks')
    functions = get(db, 'functions')


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

    # Symbols ------------------------------------------------------------------
    import_symbols(labels, functions, BASE)

main()
