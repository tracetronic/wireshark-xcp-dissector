# XCP dissector

This repository provides a dissector that enables [Wireshark](https://www.wireshark.org/) to decode [XCP](https://www.asam.net/standards/detail/mcd-1-xcp/) packets.

## Purpose and disclaimer

This dissector is mainly intended as diagnostic aid for developing and troubleshooting one's own XCP implementations.

It does not claim to be 100% complete or 100% correct, and it is no replacement for studying the specification documents of the XCP standard itself.

## Installation

To install the dissector, copy the contents of the `lua` directory to your Wireshark plugins directory.
On Windows, this is typically located at `%AppData%\Wireshark\plugins`, on Linux at `~/.config/wireshark`.

## Limitations

The supported transport layers are *XCP on Ethernet* and *XCP on CAN*.
There are no plans to add other transport layers.

The Multicast commands `GET_SLAVE_ID` and `GET_DAQ_CLOCK_MULTICAST` are not supported.

Dissecting recordings of incomplete XCP sessions may not work reliably, due to parameters negotiated early in the session influencing the structure and meaning of certain packets exchanged later on.

If DLC is set to MAX_DLC for XCP on CAN, the tail is also read as DATA for DOWNLOAD_MAX, PROGRAM_MAX and DAQ lists.

## XCP on Ethernet

If you are using a different port than 5555, you may need to right-click an XCP packet, click "decode as", optionally select the destination port number instead of the automatically chosen source port number, and choose "XCP_ETH".

In that case, the dissector assumes that the slave uses the lower port number. You may need to change the `xcp_dir` assignments in `XCP_ETH.lua` if this isn't the case for you.

## XCP on CAN
### Convert to a supported format
Some popular formats for recording CAN bus traffic are not directly supported by Wireshark. You can convert many formats e.g. with [python-can](https://github.com/hardbyte/python-can):

```cmd
pip install python-can
python -m can.logconvert input.asc output.blf
```

### Enable Dissection
* Enable the protocol (Analyze -> Enabled Protocols -> XCP_CAN)
* Set your Master and Slave CAN IDs (Edit -> Preferences -> Protocols -> XCP_CAN)
* Right click on your CAN Frame -> Decode As -> Current -> XCP_CAN

Only CAN frames whose CAN IDs match the CAN IDs configured in the protocol preferences are dissected.

## License

Copyright (c) 2024 TraceTronic GmbH

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; version 2.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

## Feedback and contact

If you have any questions, comments, requests, suggestions, etc. regarding this dissector, please contact support@tracetronic.com
