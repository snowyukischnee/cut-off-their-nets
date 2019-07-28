# cut-off-their-nets
>Today, while I'm playing some `Insurgency: Sandstorm`, my ping was nice 50-60 average, however sometime it will spike up to 1000 and I couldn't move. I've tried another match but the result has gone worse: 'the game is unplayable', I've been kicked out due to the disconnection. I stopped play games and do some homeworks but this time I can not do anything about the internet, even `Google` was inaccessible. I thinked someone have been using `netcut` or some similar software. I gone and reset the router, I was quickly peek at the MAC address of this router. Then I created a static ARP mapping and problem was solved. However, I was still mad, I've decided to write this extreme small tiny script to excommunicado them.

## Quickstarts
Not much, just install `python 3.6+` and `scapy` then everything is done
## Usage
Just add some IP addres into the `*.txt` files and run this command:
```sh
python punisher.py -g gateways.txt -t targets.txt -e excludes.txt -i 2
```
While running the script, type `quit` and press `Enter` to end the process
For more information, please run:
```sh
python punisher.py --help
```
