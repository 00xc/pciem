<div align="center">
  <img src="resources/icon.png">
</div>

<div align="center">
  A synthetic PCIe framework for host-direct driver development
</div>

<div align="center">
  https://cakehonolulu.github.io/introducing-pciem/
</div>

## How to use PCIem

1.- Choose a good target to setup the memmap= cmdline carving

2.- Execute the test_system.sh script

[!] You'll need to modify the pciem_force_phys= argument in test_system.sh to match what you chose in memmap= , this will be changed to be provided dynamically but this being still a PoC is why it's hardcoded for now

3.- Profit