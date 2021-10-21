#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from __future__ import print_function
from __future__ import unicode_literals
import itertools
import os
import shlex
import shutil
import string
from copy import copy
from collections import OrderedDict, Counter
from operator import itemgetter
from subprocess import Popen, PIPE

try:
    # Python 2.x
    zipfunc = itertools.izip_longest
    translate = lambda x: string.translate(x, string.maketrans("abcdef", "*#ABCD"))
except AttributeError:
    # Python 3.x
    zipfunc = itertools.zip_longest
    translate = lambda x: str.translate(x.decode(), str.maketrans("abcdef", "*#ABCD"))

STREAM_COLS = OrderedDict([
    ("SrcIPAddr", 15),
    ("SrcPort", 7),
    ("DstIPAddr", 15),
    ("DstPort", 7),
    ("SSRC", 10),
    ("Payload", 7),
    ("Pkts", 4),
    ("PktLoss", 7),
    ("PktLossPct", 10),
    ("MaxDelta", 8),
    ("MaxJitter", 9),
    ("MeanJitter", 10),
    ("Problems", 8),
    ("MaxSkew", 7),
    ("Ptime", 5),
    ("DSCP", 4),
    ("RFC2833Payload", 14), 
    ("RFC2833Events", 13), 
])


class Frame(object):
    """RTP Frame data class to store a few RTP frame field values."""
    __slots__ = [
        "number", "time_relative", "ip_dsfield_dscp", "ip_src",
        "udp_srcport", "ip_dst", "udp_dstport", "rtp_ssrc", "rtp_p_type",
        "rtp_timestamp", "rtp_seq", "rtpevent_event_id",
        "rtpevent_end_of_event", "rtp_payload"
    ]

    toint = lambda x: int(x) if x else None
    tostr = lambda x: x.replace(":", "")
    slot_funcs = [int, float, int, str, int, str, int, str, toint, toint, str,
        str, str, tostr, str]

    def __init__(self, *fields):
        """Initializes Frame instance attributes from fields argument.
        
        Args:
            fields (tuple): tuple of RTP Frame fields
        """
        for attr, slot_func, v in zip(self.__slots__, Frame.slot_funcs, fields):
            setattr(self, attr, slot_func(v))

    def __str__(self):
        return " ".join(
            "{0}:{1}".format(s, getattr(self, s)) for s in self.__slots__
        )

    @property
    def event_isend(self):
        """tuple(str, bool): Returns telephony event and end_of_event."""
        if self.rtpevent_event_id:
            return self.rtpevent_event_id, bool(int(self.rtpevent_end_of_event))
        elif 0 < len(self.rtp_payload) < 16 and int(self.rtp_p_type) > 95:
            return (translate(self.rtp_payload[1].encode()),
                    bool(int(self.rtp_payload[2]))
                )
        return None, False

    @property
    def Id(self):
        """tuple: Returns instance Id."""
        return (self.ip_src, self.udp_srcport, self.ip_dst, self.udp_dstport,
                self.rtp_ssrc)


class Stream(object):
    __slots__ = STREAM_COLS.keys()

    def __init__(self, *fields):
        """Initializes Stream instance attributes from fields argument.
    
        Args:
            fields (tuple): tuple of RTP Stream column values.
        """
        for attr, v in zipfunc(self.__slots__, fields, fillvalue=None):
            setattr(self, attr, v)

    @property
    def Id(self):
        """tuple: Returns instance Id."""
        return (self.SrcIPAddr, self.SrcPort, self.DstIPAddr, self.DstPort,
                self.SSRC)

    def __str__(self):
        return " ".join(
            "{0}:{1}".format(s, getattr(self, s)) for s in self.__slots__
        )

    def _asdict(self):
        """dict: Returns instance as dict."""
        return OrderedDict([(s, getattr(self, s, None)) for s in self.__slots__])

    def __eq__(self, other):
        return self._asdict() == other._asdict()

    def __ne__(self, other):
        return self._asdict() != other._asdict()


class PCAPParser(object):
    """Extract RTP Statistics from PCAP file."""
    ARGS1 = [
        "-n", "-q", "-o", "rtp.heuristic_rtp:TRUE", "-z", "rtp,streams", "-r"
    ]
    ARGS2 = [
        "-n", "-l", "-E", "occurrence=l", "-E", "separator=,", "-T", "fields"
    ]
    OVERRIDES = [
        "rtp.heuristic_rtp:TRUE", "rtcp.heuristic_rtcp:TRUE",
        "rtpevent.event_payload_type_value:95"
    ]
    FIELDS = [
        "frame.number", "frame.time_relative", "ip.dsfield.dscp", "ip.src",
        "udp.srcport", "ip.dst", "udp.dstport", "rtp.ssrc", "rtp.p_type",
        "rtp.timestamp", "rtp.seq", "rtpevent.event_id",
        "rtpevent.end_of_event", "rtp.payload"
    ]

    def __init__(self, tshark=None):
        """Initializes class instance

        Args:
            tshark (str): full path to tshark executable
        """
        self._tshark = tshark
        self.streams = {}
        self.frames = {}
        self.pcapfile = None

    def parse(self, pcapfile):
        """Parses the pcapfile.

        Args:
            pcapfile (str): full path to pcapfile

        Returns:
            None
        """
        self.pcapfile = pcapfile
        self._rtp_streams()
        self._rtp_frames()
        self._rtp_dscp()
        self._rtp_events()
        self._rtp_maxskew_ptime()

    def clear(self):
        """Clears internal state."""
        self.streams.clear()
        self.frames.clear()
        self.pcapfile = None

    def get(self):
        """dict: Returns copy of internal streams dict."""
        return copy(self.streams)

    def asdict(self, sorted=True):
        """Returns a copy of internal streams as dictionaries.

        Args:
            sorted (bool, optional): to sort streams by SSRC and SrcIPAddr
                Defaults to True

        Returns:
            dict: dictionary of dictionaries of streams
        """
        d = {k: v._asdict() for k, v in self.get().items()}
        if sorted:
            d = self._sort(d)
        return d

    def asstr(self, sorted=True):
        """Returns copy of internal streams converting values to a string.

        Args:
            sorted (bool, optional): to sort streams by SSRC and SrcIPAddr
                Defaults to True

        Returns:
            str: string of rtpstream columns and values
        """
        d = self.asdict(sorted=sorted)
        if not d:
            return ""

        out = []
        colvals = d.values()
        colnames = STREAM_COLS.keys()
        colwidths = list(STREAM_COLS.values())
    
        # Update colwidths to max length value.
        for i, colname in enumerate(colnames):
            vallens = []
            for val in colvals:
                if isinstance(val, float):
                    vallen = len("{:.2f}".format(val))
                else:
                    vallen = len(str(val[colname]))
                vallens.append(vallen)
            maxlen = max(vallens)
            if maxlen > colwidths[i]:
                colwidths[i] = maxlen

        # Append column names
        out.append(
            " ".join("{0:>{1}}".format(*z) for z in zip(colnames, colwidths))
        )

        # Append column values
        for colval in colvals:
            vals = []
            for val in colval.values():
                if val is None:
                    vals.append("")
                elif isinstance(val, float):
                    vals.append("{:.2f}".format(val))
                else:
                    vals.append(val)
            out.append(
                " ".join("{0:>{1}}".format(*z) for z in zip(vals, colwidths))
            )

        return "\n".join(out)

    def _rtp_streams(self):
        """Dumps RTP Stream Summary to 'streams' dict."""
        cmd = "{0} {1} {2}".format(
            self.tshark, " ".join(self.ARGS1), self.pcapfile
        )
        raw = self._getoutput(cmd)
        if not raw:
            return

        raw = raw.decode()
        lines = [l+"N" if l.endswith(" ") else l for l in raw.split("\n")[1:-1]]
        colnames = lines[0].strip()
        lines = lines[1:]

        if colnames.startswith("Start time"):
            colidx = [2, 3, 4, 5, 6, slice(7,-7), -7, -6, -5, -4, -3, -2, -1]
        else:
            colidx = [0, 1, 2, 3, 4, slice(5,-7), -7, -6, -5, -4, -3, -2, -1]

        columns_of_streams = [l.split() for l in lines]
        for columns_of_stream in columns_of_streams:
            try:
                stream = Stream(
                    columns_of_stream[colidx[0]],
                    int(columns_of_stream[colidx[1]]),
                    columns_of_stream[colidx[2]],
                    int(columns_of_stream[colidx[3]]),
                    columns_of_stream[colidx[4]].lower(),
                    " ".join(columns_of_stream[colidx[5]]).strip("ITU-T "),
                    int(columns_of_stream[colidx[6]]),
                    int(columns_of_stream[colidx[7]]),
                    columns_of_stream[colidx[8]][1:-1],
                    float(columns_of_stream[colidx[9]]),
                    float(columns_of_stream[colidx[10]]),
                    float(columns_of_stream[colidx[11]]),
                    columns_of_stream[colidx[12]]
                )
                self.streams[stream.Id] = stream
            except Exception as e:
                continue

    def _rtp_frames(self):
        """Extracts RTP frame fields to fields dict."""
        cmd = self.tshark
        cmd += " ".join(" -o " + x for x in self.OVERRIDES)
        cmd += " ".join(" " + x for x in self.ARGS2)
        cmd += " ".join(" -e " + x for x in self.FIELDS)
        cmd += " -r {0}".format(self.pcapfile)
        frames = self._getoutput(cmd)

        if not frames:
            return

        frames = (tuple(x.split(",")) for x in frames.decode().split("\n"))
        for frame in frames:
            try:
                frame = Frame(*frame)
                if frame.rtp_ssrc:
                    self.frames.setdefault(frame.Id, []).append(frame)
            except:
                continue

    def _rtp_dscp(self):
        """Updates streams with DSCP value."""
        for Id in self.streams:
            try:
                dscp = next(
                    self.frames[f][0].ip_dsfield_dscp
                    for f in self.frames if f == Id
                )
            except StopIteration:
                dscp = 0
            self.streams[Id].DSCP = dscp

    def _rtp_events(self):
        """Updates streams with RFC2833 events and payload type."""
        events = {}
        for Id, frames in self.frames.items():
            for f in frames:
                if f.event_isend[0]:
                    events.setdefault(Id, []).append(
                        (f.event_isend, f.rtp_p_type)
                    )
        for Id, stream in self.streams.items():
            if Id in events:
                self.streams[Id].RFC2833Events = self._get_events(events[Id])
                self.streams[Id].RFC2833Payload = events[Id][0][1]
            else:
                self.streams[Id].RFC2833Events = None
                self.streams[Id].RFC2833Payload = None

    def _rtp_maxskew_ptime(self):
        """Update streams with maximum skew and ptime values."""
        for Id, fs in self.frames.items():
            if Id not in self.streams:
                continue
            payload = self.streams[Id].RFC2833Payload
            mediaframes = [f for f in fs if f.rtp_p_type != payload]
            max_skew, ptime = self._get_maxskew_ptime(mediaframes)
            self.streams[Id].MaxSkew = max_skew
            self.streams[Id].Ptime = ptime

    def _sort(self, d):
        """dict: Returns d sorted by SSRC and SrcIPAddr."""
        return OrderedDict((k, d[k]) for k in sorted(d, key=itemgetter(4, 0)))

    @staticmethod
    def _get_events(event_isend_tuples):
        """Extracts RFC2833 unrepeated end events.

        Args:
            event_isend_tuples (list): list of frame event_isend tuples

        Returns:
            str: unrepeated end events
        """
        len_event = len(event_isend_tuples)
        events = []
        for i, ((event, isend), _) in enumerate(event_isend_tuples):
            if isend:
                if i+1 < len_event and not event_isend_tuples[i+1][0][1]:
                    events.append(event)
                elif i+1 == len_event:
                    events.append(event)
        return "".join(events)

    @staticmethod
    def _get_maxskew_ptime(mediaframes):
        """Extracts maximum skew and ptime from packets.

        Args:
            mediaframes (list): list of media frames

        Returns:
            tuple(str, str): (absolute) maximum skew and ptime
        """
        fst_frametime = mediaframes[0].time_relative
        fst_rtptime = mediaframes[0].rtp_timestamp
        ptimes = []
        skews = []

        for i, x in enumerate(mediaframes[1:], start=1):
            frametime = x.time_relative
            try:
                prev_frametime = mediaframes[i-1].time_relative
            except IndexError:
                prev_frametime = frametime
            exp = (x.rtp_timestamp - fst_rtptime) / 8000.0
            real = frametime - fst_frametime
            skews.append(round((exp - real) * 1000, 2))
            ptimes.append("{0:.2f}".format(round(frametime - prev_frametime, 2)))

        try:
            ptime = int(float(Counter(ptimes).most_common(1)[0][0]) * 1000)
        except IndexError:
            ptime = None

        try:
            left_max = sorted(skews)[0]
            right_max = sorted(skews)[-1]
            if abs(left_max) > abs(right_max):
                max_skew = left_max
            else:
                max_skew = right_max
        except IndexError:
            max_skew = None

        return max_skew, ptime

    @property
    def tshark(self):
        """str: Returns full path to tshark if found in $PATH."""
        if self._tshark is None:
            try:
                tshark = shutil.which("tshark")
            except AttributeError:
                try:
                    tshark = next(
                        os.path.join(path, "tshark") for path in
                        os.getenv("PATH").split(":") if
                        os.path.exists(os.path.join(path, "tshark"))
                    )
                except StopIteration:
                    tshark = ""
            if not tshark:
                raise RuntimeError("Could not find tshark")
            self._tshark = tshark
        return self._tshark

    @staticmethod
    def _getoutput(cmd):
        """Runs cmd arg in subprocess and returns the output.

        Args:
            cmd (str): shell command to run

        Returns:
            str: output of cmd
        """
        proc = Popen(shlex.split(cmd), stdout=PIPE, stderr=PIPE)
        data, _ = proc.communicate()
        data = data.strip()
        if not data and proc.returncode:
            return ""
        return data

    def __len__(self):
        return len(self.streams)

    def __str__(self):
        return self.asstr()


if __name__ == "__main__":
    import glob
    pcapparser = PCAPParser()
    for file in glob.glob("data/*"):
        pcapparser.parse(file)
    print(pcapparser)
