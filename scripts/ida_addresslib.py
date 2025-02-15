# Credits to Vermunds for v1 and v2 address lib and base code for this script

import idaapi
import ida_kernwin
import ida_nalt
import struct
import pickle
import csv
import idc
import idautils

# Global variable to store the address-ID mappings
address_to_id = {}
id_to_address = {}
address_library_loaded = False

ACTION_CLEARDB = "addresslib:clear"
ACTION_LOAD_V1 = "addresslib:load_v1"
ACTION_LOAD_V2 = "addresslib:load_v2"
ACTION_LOAD_VR = "addresslib:load_vr"
ACTION_JUMPTO = "addresslib:jumpto"


def get_file_path():
    idb_path = ida_nalt.get_input_file_path()
    return idb_path + ".ald"


def save_address_library():
    global id_to_address, address_library_loaded
    file_path = get_file_path()
    with open(file_path, "wb") as file:
        data_to_save = {
            "id_to_address": id_to_address,
            "address_library_loaded": address_library_loaded,
        }
        pickle.dump(data_to_save, file)


def load_address_library():
    global address_to_id, id_to_address, address_library_loaded
    file_path = get_file_path()
    try:
        with open(file_path, "rb") as file:
            data_loaded = pickle.load(file)
            id_to_address = data_loaded.get("id_to_address", {})
            address_library_loaded = data_loaded.get("address_library_loaded", False)
            address_to_id = {v: k for k, v in id_to_address.items()}
    except (FileNotFoundError, EOFError, pickle.UnpicklingError):
        id_to_address = {}
        address_to_id = {}
        address_library_loaded = False


def read_data(file, dtype):
    if dtype == "unsigned char":
        return int.from_bytes(file.read(1), byteorder="little", signed=False)
    elif dtype == "unsigned short":
        return int.from_bytes(file.read(2), byteorder="little", signed=False)
    elif dtype == "unsigned int":
        return int.from_bytes(file.read(4), byteorder="little", signed=False)
    elif dtype == "unsigned long long":
        return int.from_bytes(file.read(8), byteorder="little", signed=False)
    else:
        return None


def load_v2(file_path):
    _ver = [0, 0, 0, 0]
    _moduleName = ""
    _data = {}
    _rdata = {}

    with open(file_path, "rb") as file:
        format = struct.unpack("i", file.read(4))[0]
        if format != 2:
            ida_kernwin.warning(f"Error: Unknown address library version: {format}\n")
            return False

        _ver = struct.unpack("iiii", file.read(16))
        _verStr = ".".join(map(str, _ver))

        tnLen = struct.unpack("i", file.read(4))[0]
        if tnLen < 0 or tnLen >= 0x10000:
            return False

        if tnLen > 0:
            _moduleName = file.read(tnLen).decode("utf-8")

        ptrSize = struct.unpack("i", file.read(4))[0]
        addrCount = struct.unpack("i", file.read(4))[0]

        pvid = poffset = 0
        for _ in range(addrCount):
            type_ = read_data(file, "unsigned char")
            if type_ is None:
                return False
            low = type_ & 0xF
            high = type_ >> 4

            if pvid is not int:
                raise Exception("pvid not int")

            if low == 0:
                id = read_data(file, "unsigned long long")
            elif low == 1:
                id = pvid + 1
            elif low == 2:
                b1 = read_data(file, "unsigned char")
                id = pvid + b1
            elif low == 3:
                b1 = read_data(file, "unsigned char")
                id = pvid - b1
            elif low == 4:
                w1 = read_data(file, "unsigned short")
                id = pvid + w1
            elif low == 5:
                w1 = read_data(file, "unsigned short")
                id = pvid - w1
            elif low == 6:
                w1 = read_data(file, "unsigned short")
                id = w1
            elif low == 7:
                d1 = read_data(file, "unsigned int")
                id = d1
            else:
                clear_db()
                return False

            tpoffset = poffset // ptrSize if (high & 8) != 0 else poffset

            if tpoffset is not int:
                raise Exception("tpoffset not int")

            if (high & 7) == 0:
                address = read_data(file, "unsigned long long")
            elif (high & 7) == 1:
                address = tpoffset + 1
            elif (high & 7) == 2:
                b2 = read_data(file, "unsigned char")
                address = tpoffset + b2
            elif (high & 7) == 3:
                b2 = read_data(file, "unsigned char")
                address = tpoffset - b2
            elif (high & 7) == 4:
                w2 = read_data(file, "unsigned short")
                address = tpoffset + w2
            elif (high & 7) == 5:
                w2 = read_data(file, "unsigned short")
                address = tpoffset - w2
            elif (high & 7) == 6:
                w2 = read_data(file, "unsigned short")
                address = w2
            elif (high & 7) == 7:
                d2 = read_data(file, "unsigned int")
                address = d2
            else:
                raise Exception("Invalid type")

            if address is None or id is None:
                raise Exception("address or id is none")

            if (high & 8) != 0:
                address *= ptrSize

            _data[id] = address
            _rdata[address] = id

            poffset = address
            pvid = id

    return _verStr, _moduleName, _data, _rdata


def load_address_library_v1():
    global id_to_address
    global address_to_id
    global address_library_loaded

    file_path = ida_kernwin.ask_file(False, "*.bin", "Select Address Library file")
    ida_kernwin.msg(f"Loading file {file_path}\n")

    if not file_path:
        return

    with open(file_path, "rb") as file:
        clear_db()
        file.read(8)  # skip the header
        while True:
            offset_bytes = file.read(8)
            if not offset_bytes:
                break  # End of file
            offset = int.from_bytes(offset_bytes, byteorder="little", signed=False)

            address_bytes = file.read(8)
            if not address_bytes:
                ida_kernwin.warning("Error: Incomplete data pair in file.\n")
                clear_db()
                return

            address = int.from_bytes(address_bytes, byteorder="little", signed=False)

            id_to_address[offset] = address
            address_to_id[address] = offset

    address_library_loaded = True
    save_address_library()
    ida_kernwin.msg(f"Loaded Address Library file {file_path}.\n")


def load_address_library_v2():
    global id_to_address
    global address_to_id
    global address_library_loaded

    file_path = ida_kernwin.ask_file(False, "*.bin", "Select Address Library file")
    ida_kernwin.msg(f"Loading file {file_path}\n")

    if file_path:
        clear_db()

        retVal = load_v2(file_path)

        if retVal is False:
            return

        verStr, moduleName, data, rdata = retVal
        loaded_module_name = ida_nalt.get_root_filename()

        if moduleName != loaded_module_name:
            clear_db()
            ida_kernwin.warning(
                f"Error: This Address Library is for {moduleName}. The current file is {loaded_module_name}. Loading aborted.\n"
            )
            return

        id_to_address = data
        address_to_id = rdata
        address_library_loaded = True
        save_address_library()

        ida_kernwin.msg(f"Loaded Address Library for {moduleName} runtime {verStr}\n")


def load_address_library_vr():
    global id_to_address
    global address_to_id
    global address_library_loaded

    seid_to_aeid = {}

    se_ae_path = ida_kernwin.ask_file(
        False, "se_ae.csv", "Select se_ae file(from skyrim_vr_address_library)"
    )
    ida_kernwin.msg(f"Loading file {se_ae_path}\n")

    with open(se_ae_path, "r") as file:
        csvFile = csv.reader(file)
        next(csvFile, None)  # skip the header
        for row in csvFile:
            seid_to_aeid[int(row[0])] = int(row[1])

    file_path = ida_kernwin.ask_file(
        False, "database.csv", "Select vr Address Library file"
    )
    ida_kernwin.msg(f"Loading file {file_path}\n")

    base_address = ida_nalt.get_imagebase()

    if not file_path:
        return

    with open(file_path, "r") as file:
        clear_db()
        csvFile = csv.reader(file)
        next(csvFile, None)  # skip the header
        for row in csvFile:
            seid = int(row[0])
            address = int(row[2], 16)

            address_offset = address - base_address

            id_to_address[seid] = address_offset
            address_to_id[address_offset] = seid

            ae_id = seid_to_aeid.get(seid, None)

            ae_id_msg = ""
            if ae_id is None:
                ae_id_msg = "AE ID: Not found in se_ae.csv\n"
            else:
                ae_id_msg = f"AE ID: {ae_id}\n"

            print(f"se id: {seid}, address: 0x{(address):X}, name: {row[4]}")
            cmt = f"SE ID: {seid} ADDR: 0x{int(row[1], 16):X}\n{ae_id_msg}STATUS: {row[3]}\nVR ADDR: 0x{address:X}\n{row[4]}"
            success = idc.set_func_cmt(address, cmt, 1)
            if success is not True:
                idc.set_cmt(address, cmt, False)
            else:
                dism_addr = list(idautils.FuncItems(address))
                for c in range(len(dism_addr)):
                    instruction_addr = dism_addr[c]
                    instruction_type = idc.print_insn_mnem(instruction_addr)
                    if instruction_type == "call" or instruction_type == "jmp":
                        if ae_id is None:
                            idc.set_cmt(
                                instruction_addr,
                                f"REL::RelocationID({seid}, 0).address() + REL::Relocate(0x0, 0x0, 0x{instruction_addr-address:X})",
                                False,
                            )
                        else:
                            idc.set_cmt(
                                instruction_addr,
                                f"REL::RelocationID({seid}, {ae_id}).address() + REL::Relocate(0x0, 0x0, 0x{instruction_addr-address:X})",
                                False,
                            )

    address_library_loaded = True
    save_address_library()
    ida_kernwin.msg(f"Loaded Address Library file {file_path}.\n")


def get_id_by_address(address):
    global address_to_id
    global address_library_loaded

    if not address_library_loaded:
        ida_kernwin.warning("No Address Library is loaded.")
        return None

    base_address = ida_nalt.get_imagebase()
    adjusted_address = address - base_address

    return address_to_id.get(adjusted_address, None)


def get_address_by_id(id_to_search):
    global id_to_address
    global address_library_loaded

    if not address_library_loaded:
        ida_kernwin.warning("No Address Library is loaded.")
        return None

    base_address = ida_nalt.get_imagebase()
    address_offset = id_to_address.get(id_to_search, None)

    if address_offset is not None:
        return base_address + address_offset
    return None


def clear_db():
    global id_to_address
    global address_to_id
    global address_library_loaded

    address_library_loaded = False

    id_to_address = {}
    address_to_id = {}
    save_address_library()


class AddressLibraryPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Plugin to interact with Address Library IDs"
    help = ""
    wanted_name = "Address Library Plugin"
    wanted_hotkey = ""

    def init(self):
        load_address_library()
        register_actions()
        return idaapi.PLUGIN_KEEP

    def run(self, _):
        pass

    def term(self):
        pass


def register_actions():
    load_action_v1_desc = idaapi.action_desc_t(
        ACTION_LOAD_V1,
        "Load address library v1 (Fallout 4) ",
        IDACtxEntry(load_address_library_v1),
        None,
        "Loads Address Library database version 1",
    )

    load_action_v2_desc = idaapi.action_desc_t(
        ACTION_LOAD_V2,
        "Load address library v2 (Skyrim, Starfield) ",
        IDACtxEntry(load_address_library_v2),
        None,
        "Loads Address Library database version 2",
    )

    load_action_vr_desc = idaapi.action_desc_t(
        ACTION_LOAD_VR,
        "Load address library vr (Skyrim, Fallout) ",
        IDACtxEntry(load_address_library_vr),
        None,
        "Loads Address Library database version VR (database.csv)",
    )

    clear_db_action = idaapi.action_desc_t(
        ACTION_CLEARDB,
        "Clear loaded database",
        IDACtxEntry(clear_db_handler),
        None,
        "Clears any loaded Address Library database",
    )

    jump_to_id_action_desc = idaapi.action_desc_t(
        ACTION_JUMPTO,
        "Jump to Address Library ID...",
        IDACtxEntry(get_id_handler),
        None,
        "Gets the ID for the current address",
    )

    idaapi.register_action(load_action_v1_desc)
    idaapi.register_action(load_action_v2_desc)
    idaapi.register_action(load_action_vr_desc)
    idaapi.register_action(clear_db_action)
    idaapi.register_action(jump_to_id_action_desc)

    idaapi.attach_action_to_menu(
        "Edit/Address Library/", ACTION_LOAD_V1, idaapi.SETMENU_APP
    )
    idaapi.attach_action_to_menu(
        "Edit/Address Library/", ACTION_LOAD_V2, idaapi.SETMENU_APP
    )
    idaapi.attach_action_to_menu(
        "Edit/Address Library/", ACTION_LOAD_VR, idaapi.SETMENU_APP
    )
    idaapi.attach_action_to_menu(
        "Edit/Address Library/", ACTION_CLEARDB, idaapi.SETMENU_APP
    )
    idaapi.attach_action_to_menu(
        "Jump/Jump to file offset...", ACTION_JUMPTO, idaapi.SETMENU_APP
    )


def clear_db_handler():
    global address_library_loaded

    if not address_library_loaded:
        ida_kernwin.warning("No Address Library is loaded.")
        return
    clear_db()
    ida_kernwin.msg("Loaded Address Library database has been cleared.\n")


def get_id_handler():
    global address_library_loaded

    if not address_library_loaded:
        ida_kernwin.warning("No Address Library is loaded.")
        return

    current_id = get_id_by_address(idaapi.get_screen_ea())

    result = None
    if current_id is not None:
        current_id_str = f"{current_id}"
        result = ida_kernwin.ask_str(current_id_str, 0, "Enter Address Library ID")
    else:
        result = ida_kernwin.ask_str("0", 0, "Enter Address Library ID")

    if result is not None:
        user_id = int(result)
        address = get_address_by_id(user_id)
        if address is not None:
            ida_kernwin.jumpto(address)
        else:
            ida_kernwin.warning(f"Invalid ID: {user_id}.")


class IDACtxEntry(idaapi.action_handler_t):
    """
    A basic Context Menu class to utilize IDA's action handlers.
    """

    def __init__(self, action_function):
        idaapi.action_handler_t.__init__(self)
        self.action_function = action_function

    def activate(self, ctx):
        """
        Execute the embedded action_function when this context menu is invoked.
        """
        self.action_function()
        return 1

    def update(self, ctx):
        """
        Ensure the context menu is always available in IDA.
        """
        return idaapi.AST_ENABLE_ALWAYS


def PLUGIN_ENTRY():
    return AddressLibraryPlugin()
