from colorama import Fore, Back, Style
from colorama import init as color_init

def good(line):
    print Fore.GREEN + Style.BRIGHT + "[+]" + Style.RESET_ALL, line

def meh(line):
    print Fore.BLUE + Style.BRIGHT + "[*]" + Style.RESET_ALL, line

def error(line):
    print Fore.RED + Style.BRIGHT + "[-] !!! " + Style.NORMAL, line, Style.BRIGHT + "!!!"

def bad(line):
    print Fore.RED + Style.BRIGHT + "[-]" + Style.RESET_ALL, line

def info(line):
    print Fore.WHITE + Style.BRIGHT + "[*]" + Style.RESET_ALL, line
