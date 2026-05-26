RUDPTransfer stability patch

Replace these files in your project root:
- main_kivy.py
- client.py
- server.py
- file_transfer_common.py

Main changes:
- User-visible error reasons for approval timeout, receiver rejection, receiver save path errors, disk space shortage, network no-progress timeout, output open failure, and completion timeout.
- Retry button on the sender side. Failed transfers can be retried with the same file and receiver settings.
- Receiver-side save directory validation and disk space check before accepting a transfer.
- Existing target file handling in the receiver confirmation dialog: auto rename, overwrite, or cancel.
- Receiver idle-timeout message in the GUI.
- Sender no-progress timeout option.

After replacing files, run:
  python main_kivy.py

Rebuild:
  rmdir /s /q build
  rmdir /s /q dist
  pyinstaller --clean RUDPTransfer.spec
