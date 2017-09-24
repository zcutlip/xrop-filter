# Xrop Filter

## Description
A tool that parses and filters the output of xrop to help you find that needle in a haystack of rop gadgets. You can filter based on:

* One or more prohibited instructions. E.g., if need to avoid touching the stack, you might filter out `call`, `pop`, and `ret` instructions.
* One or more registers. E.g., you might want to avoid any access of `%rbx`.
* Prohibted instructions matching a perl-compatible regular expression, such as `jmp\s+rbx`.
* A required instruction matching a perl-compatible regular expression, such as `xor\s+rax,rax`.

## Usage
Coming soon