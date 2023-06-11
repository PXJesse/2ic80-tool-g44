# 2IC80 tool

*This is the Git repository for the tool developed by group 44 of 2IC80, 2022-2023. It implements the default project.*


## Tool description

The tool in this repository is a full-fledged security attacking tool written in `Python`. It implements (a combination of) the following three attacks:

1. ARP poisoning
2. DNS spoofing
3. SSL stripping


## Executing the tool

**Prerequisites:**
- `scapy`

Install the prerequisites by running (Python 2.7):

Upgrading your python 2.7 installation:
```
sudo apt-get install python-dev libssl-dev libnetfilter-queue-dev build-essential
```

```
pip install --upgrade "pip < 21.0"
pip install setuptools
pip install netfilterqueue
pip install scapy
```

**The tool:**

On a device with Python installed, run the following in your command line:

```
python tool.py
```

**Hints**:
- To view the available arguments, use the `-h` argument after the statement above.
- On some Python installations you'll need to use `python3` instead of `python`.
- Any Python version >= 2.7 is supported.



## Contribution

This tool is made by group 44.

