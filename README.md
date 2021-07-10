# MailSync
This program runs as a daemon, syncing your remote IMAP accounts to
your maildir directories. It has two modes:

1. Connect: It establishes a permanent connection to the server and
   waits for the server to push mail to the client.
2. Sync: It connects to the server and fetches all the available mail

In Connect mode it syncs first and then does the permanent connection.

This program can be configured to run hooks after fetching mail.

# Copyright
The entire program is licensed under the GNU Affero General Public
License version 3.0 or later. Refer to the [LICENSE.md](./LICENSE.md)
file for more details.

Copyright 2021 Pedro Gomez Martin
