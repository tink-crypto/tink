# Tinkey is a command-line tool to manage keys for Tink.

**Usage**: `tinkey <command> [<args>]

Available commands:

 * `add`: Generates and adds a new key to an existing keyset.
 * `change-master-key`: Changes the master key of a keyset. The keyset will be
   encrypted with the new master key.
 * `create`: Creates a new keyset.
 * `create-public-keyset`: Creates a public keyset from an existing private keyset.
 * `create-key-template`: Creates a new key template.
 * `destroy`: Destroys a specified key in a keyset.
 * `disable`: Disables a specified key in a keyset.
 * `enable`: Enables a specified key in a keyset.
 * `list`: Lists keys in a keyset.
 * `rotate`: Performs a key rotation in a keyset.

To obtain info about arguments available/required for a command, run `tinkey
<command>` without further arguments.
