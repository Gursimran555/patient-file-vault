"""python -m vault demo   - a short walkthrough on a throwaway vault"""

import sys
import tempfile

from . import AccessDeniedError, IntegrityError, Vault, new_master_key


def demo() -> int:
    with tempfile.TemporaryDirectory() as d:
        vt = Vault(d, new_master_key())
        vt.bootstrap_admin("it_admin", "admin-passphrase-2026")
        admin = vt.login("it_admin", "admin-passphrase-2026")
        for user, pw, group in [("dr_smith", "stethoscope-blue-41", "doctors"),
                                ("dr_jones", "cardiac-rhythm-77", "doctors"),
                                ("nurse_amy", "lantern-quiet-river-7", "nurses")]:
            vt.register(user, pw)
            vt.assign_group(admin, user, group)
        smith = vt.login("dr_smith", "stethoscope-blue-41")
        jones = vt.login("dr_jones", "cardiac-rhythm-77")
        amy = vt.login("nurse_amy", "lantern-quiet-river-7")

        vt.create_file(smith, "patient_101.txt", "Patient 101: diagnosis - hypertension", 0o640)
        vt.create_file(smith, "ward_notes.txt", "Ward B rounds at 9am", 0o664)
        print("dr_smith's view:")
        for f in vt.list_files(smith):
            print(f"  {f['perms']}  {f['owner']:<9} {f['group']:<8} {f['name']}")
        print("nurse_amy's view:")
        for f in vt.list_files(amy):
            print(f"  {f['perms']}  {f['owner']:<9} {f['group']:<8} {f['name']}")

        print("\nreads:")
        for who, tok in [("dr_jones (group)", jones), ("nurse_amy (other)", amy)]:
            try:
                vt.read_file(tok, "patient_101.txt")
                print(f"  {who:18} patient_101.txt -> allowed")
            except AccessDeniedError:
                print(f"  {who:18} patient_101.txt -> denied")

        print("\nflip one byte of patient_101.txt on disk, then read it:")
        blob = vt._blob(vt._meta("patient_101.txt")["id"])
        data = bytearray(blob.read_bytes())
        data[-1] ^= 1
        blob.write_bytes(bytes(data))
        try:
            vt.read_file(smith, "patient_101.txt")
        except IntegrityError as exc:
            print(f"  {exc}")

        print("\naccess history for patient_101.txt (admin only):")
        for e in vt.access_history(admin, "patient_101.txt"):
            print(f"  #{e['seq']:<3} {e['actor']:<10} {e['action']:<7} {e['outcome']}")
        print(f"\naudit chain intact: {vt.audit.verify()[0]}")
        vt.close()
    return 0


if __name__ == "__main__":
    if sys.argv[1:] != ["demo"]:
        print("usage: python -m vault demo      (attacks: python -m vault.attacks)")
        sys.exit(2)
    sys.exit(demo())
