# 2IC80 tool

*This is the Git repository for the tool developed by group 44 of 2IC80, 2022-2023. It implements the default project.*


## Tool description

The tool in this repository is a full-fledged security attacking tool written in `Python`. It implements (a combination of) the following three attacks:

1. ARP poisoning
2. DNS spoofing
3. ~~SSL stripping~~ unfortunately, SSL stripping is as of yet not functional


## Executing the tool

### Prerequisites

DISCLAIMER: The following prerequisites are based on the configuration of the M3 Linux Mint attacker machine as provided by the course 2IC80 — Lab on Offensive Computer Security, 2022-2023. If your attacker machine does not have the same configuration as M3, your system might require more packages to be installed and/or upgraded.

Installing the software prerequisites:
```
sudo apt-get install python-dev libssl-dev libnetfilter-queue-dev build-essential
```

Installing the Python prerequisites:
```
pip install --upgrade "pip < 21.0"
pip install setuptools
pip install netfilterqueue
pip install scapy
```

Note that the `pip` commands above might require `sudo` to be executed successfully.

### Executing the tool

On a device with Python 2.7 and the prerequisites installed, run the following in your command line:

```
python tool.py
```

The tool will present you with an interactive menu. Follow the instructions on the screen to execute the desired attack.


## Contribution

This tool is made by group 44.
