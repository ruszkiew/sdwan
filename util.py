###############################################################################

import re

# DICTIONARY VARIABLE FIND / PRINT

def var_find(dkey, dval, dret, d):
    for k, v in d.items():                            # pylint: disable=unused-variable
        if isinstance(v, dict):
            if dkey in v.keys():
                if(v[dkey] == dval):
                    print('       var: ' + v[dret])
            var_find(dkey, dval, dret, v)
        elif isinstance(v, list):
            for i in v:
                if isinstance(i, dict):
                    var_find(dkey, dval, dret, i)
    return

# DICTIONARY LIST FIND / PRINT

def list_find(d,l):
    for k1, v1 in d.items():                         # pylint: disable=unused-variable
        if isinstance(v1,dict):
            list_find(v1,l)
        elif isinstance(v1,list):
            for i in v1:
                if isinstance(i,dict):
                    list_find(i,l)
        else:
            for k2, v2 in l.items():
                if k2 == v1:
                    print('         list: ' + v1 + ' : ' + v2['type'] +
                      " "*(10 - len(v2['type'])) + ': ' + v2['name'])
    return


# SEARCH AND REPLACE ID

def id_fix(oldid, newid, drc):
    pattern = re.compile(oldid)
    for dirpath, dirname, filename in os.walk(drc):  # pylint: disable=unused-variable
        for fname in filename:
            path = os.path.join(dirpath, fname)
            try:
                strg = open(path).read()
                if re.search(pattern, strg):
                    strg = strg.replace(oldid, newid)
                    f = open(path, 'w')
                    f.write(strg)
                    print('  Updated ID in file' + path)
                f.close()
            except:
                pass
    return

###############################################################################
