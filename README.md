# Ivanti-ICT-Snapshot-decryption

Is a simple Script to decryption the Ivanti ICT-Snapshot based on https://github.com/rxwx/pulse-meter/blob/main/pulse-meter.py

In this script, only the decryption function has been retained. This makes it simple and less error-prone

### Running

First you will need to install the dependencies:

```
python -m venv env
source env/bin/activate
pip install -r requirements.txt
```

```
python3 Ivanti_ICT-Snapshot_decryption.py decryption ict-snapshot.encrypted
2024-02-08 21:56:02,492 - INFO - Parsing snapshot file: ict-snapshot.encrypted
2024-02-08 21:56:02,492 - DEBUG - Decrypted Snapshot
```
If it works, you get a file names `ICT-Snapshot.tar`

### got the Snapshot from the Ivanti-System
You can obtain the snapshot by logging into the admin interface and going to `/dana-admin/dump/dump.cgi`.
From here, click the "Take Snapshot" button, wait for it to complete and then download the "Admin generated snapshot" file.

### References
* https://github.com/rxwx/pulse-meter/
* https://www.volexity.com/blog/2024/01/10/active-exploitation-of-two-zero-day-vulnerabilities-in-ivanti-connect-secure-vpn/
* https://www.mandiant.com/resources/blog/suspected-apt-targets-ivanti-zero-day
* https://forums.ivanti.com/s/article/CVE-2023-46805-Authentication-Bypass-CVE-2024-21887-Command-Injection-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure-Gateways?language=en_US
* https://forums.ivanti.com/s/article/KB-CVE-2023-46805-Authentication-Bypass-CVE-2024-21887-Command-Injection-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure-Gateways?language=en_US
* https://attackerkb.com/topics/AdUh6by52K/cve-2023-46805/rapid7-analysis
