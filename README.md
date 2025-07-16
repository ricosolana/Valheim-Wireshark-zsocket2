# Valheim-Wireshark-zsocket2

Wireshark Dissector Lua Plugin for Valheim (**TCP ONLY**)

<img width="961" height="441" alt="image" src="https://github.com/user-attachments/assets/b9a24732-9059-4db5-a7e2-0a6b22d568ee" />

## Installation

- Open the plugins folder within Wireshark `Help -> About Wireshark -> Folders -> Personal Lua Plugins (Lua scripts)`
- Extract folder `zsocket2` into plugins folder
- Restart Wireshark
- TCP port 2456 will be automatically dissected

## Capturing

- Make sure your Wireshark capture begins before starting a Valheim network session so that the stream does not get cut-off
- Wireshark display filter: `not valheimzs2.pingpong.type and not valheimzs2.playerlist.host and not valheimzs2.nettime.time and not valheimzs2.zdodata.datarev and valheimzs2`
- To capture only TCP port 2456 packets (to save resources), open the interface (`any` on Linux) with filter `tcp port 2456`
  - See https://wiki.wireshark.org/CaptureFilters

## TODO
- Plugin has been outdated for a while, consider updating? new RPC's, fix display issues, other quirks...
- Fix ServerHandshake
