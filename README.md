# Host scanner

This script scans a given IP address or network, retrieves some informations about active devices.

## Features
- Scan a single IP or an entire network range
- Detect active hosts via ARP request
- Retrieve MAC address

## Table of Contents

- [Installation](#installation)
- [Requirements](#requirements)
- [Usage](#usage)
- [License](#license)
- [Contact](#contact)

## Installation

1. Clone or download this repository.
2. Open **Command Prompt (cmd) as Administrator**.
3. Install required dependencies if needed:
   ```sh
   pip install scapy
   ```

## Requirements

This script requires:
- Python 3.x
- scapy
- Administrator privileges

## Usage

Run the script with the following arguments:

Scan a single IP:
```sh
python network_scanner.py -i 192.168.1.53
```

Scan an entire network:
```sh
python network_scanner.py -i 192.168.1.0/24
```

## License

Include the project's license information. For example: This project is licensed under the [Creative Commons NonCommercial License (CC BY-NC)](https://creativecommons.org/licenses/by-nc/4.0/deed.en).

## Contact

Contact me: jakub1.gniadek@gmail.com