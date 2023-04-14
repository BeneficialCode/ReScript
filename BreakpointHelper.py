import idc

def main():
    minEA = idc.ida_ida.inf_get_min_ea()
    maxEA = idc.ida_ida.inf_get_max_ea()
    startEA = minEA
    while startEA < maxEA:
        ea = idc.ida_search.find_text(startEA,0,0,"repne scasb",idc.ida_search.SEARCH_DOWN)
        if ea == idc.BADADDR:
            break
        print(hex(ea))
        idc.add_bpt(ea,0)
        startEA = idc.next_head(ea)

if __name__ == '__main__':
    main()