RUDPTransfer implicit-offset resume patch

Changed files:
- file_transfer_common.py
- client.py
- server.py
- main_kivy.py
- RUDPTransfer.spec
- requirements.txt
- build_requirements.txt

Implemented:
1. FILE header version 2 with transfer_id, resume_supported and mtime_ns.
2. Receiver keeps .part and .part.meta.json after an interrupted transfer.
3. Receiver detects resumable partial files by matching transfer_id/full SHA256, size and payload_size.
4. Receiver approval popup can choose Resume / Overwrite / Cancel when a resumable .part exists.
5. Receiver sends ACCEPT with resume=true and resume_offset.
6. Sender reads resume_offset, aligns it to payload_size, seeks to that offset and sends only the remaining file body.
7. RUDP per-session sequence range and EOF are recalculated for the remaining body portion.
8. Final SHA256 still verifies the whole received file before renaming .part to the final file.
9. Resume meta is removed after successful completion.

This patch uses implicit file offset. The RUDP DATA payload format is unchanged; resume is negotiated at the file request/decision layer.
