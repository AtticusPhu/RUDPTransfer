RUDPTransfer receiver identity / per-receiver pin patch

Changed files:
- main_kivy.py
- client.py

Implemented:
1. Local receiver identity key remains permanently stored under the user data directory:
   %LOCALAPPDATA%\RUDPTransfer\rudp_receiver_ed25519.key on Windows.
2. Sender-side trusted receiver identities now use one pin file per receiver endpoint:
   %LOCALAPPDATA%\RUDPTransfer\receiver_pins\<ip>_<port>.pin
3. The GUI sender no longer uses the old global rudp_receiver_ed25519.pin for all receivers.
4. If a pinned receiver identity changes, the sender stops the handshake quickly and reports a user-facing receiver_identity_changed error instead of retrying SYN until the retry limit.
5. The GUI keeps the discovered receiver selection, IP field, port field, and worker launch arguments synchronized. Manual edits to IP/port override stale discovery selections.

Operational notes:
- If a receiver was reinstalled or regenerated its identity key, delete only that receiver's pin file under receiver_pins and connect again to trust the new identity.
- Do not delete rudp_receiver_ed25519.key unless you intentionally want that machine to become a new receiver identity.

Rebuild:
  rmdir /s /q build
  rmdir /s /q dist
  pyinstaller --clean RUDPTransfer.spec
