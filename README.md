# rtpstreams
Extracts the summary of RTP streams from pcap files in additions to RFC2833 events, Maxskew and DSCP values.

## Example
```
>>> import rtpstreams
>>> import glob
>>> pcapparser = rtpstreams.PCAPParser()
>>> for file in glob.glob("data/*"):
...     pcapparser.parse(file)
...
>>> print(pcapparser)

      SrcIPAddr SrcPort       DstIPAddr DstPort       SSRC            Payload Pkts PktLoss PktLossPct MaxDelta MaxJitter MeanJitter Problems MaxSkew Ptime DSCP RFC2833Payload   RFC2833Events
  10.130.93.242    6008   10.130.88.141   35094 0x0c7f3cc7     g729, rtpevent 1704       0       0.0%   111.08     28.71       1.99        N   -3.17    20    0             96 123456*0#112233
  10.130.93.242    6188   10.130.88.141   35086 0x36ad269e g711A, RTPType-101 1108       0       0.0%   110.09     29.25       1.79        N   20.14    20    0            101       123456*0#
  10.130.88.141   35060   10.130.93.242    6138 0x4e0691fd g711A, RTPType-127 3308       0       0.0%    78.12     13.70       0.11        N  -58.51    20   46            127       123456*0#
  10.130.93.242    6138   10.130.88.141   35060 0x5e453cef              g711A 3272       0       0.0%   121.16      7.10       0.18        N  -65.93    20    0                               
  10.130.88.141   35086   10.130.93.242    6188 0x60e091f2 g711A, RTPType-101 1143       0       0.0%    25.90     13.84       0.09        N   -5.59    20   46            101       123456*0#
  10.130.88.141   35094   10.130.93.242    6008 0x7f239de8     g729, rtpevent 1762       0       0.0%    25.46     14.04       0.08        N   -5.25    20   46             96 123456*0#112233
```

## Requirements

- Python 2.7 or 3.x
- Tshark

## License

MIT, see: LICENSE.txt

## Author

Szabolcs Szokoly <a href="mailto:sszokoly@pm.me">sszokoly@pm.me</a>
