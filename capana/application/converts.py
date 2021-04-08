from capana.application.base import BackEndError

def row_to_dict(row,columns):
    if len(row) == len(columns):
        r_dict = {}
        for i in range(len(row)):
            r_dict[columns[i]] = row[i]
        return r_dict
    print(row,columns)
    raise BackEndError("row_to_dict: len(row) != len(columns)")

def convert_conv_table(src):
        """
        src:

        ================================================================================
        IPv4 Conversations
        Filter:ip.addr==192.168.2.147
                                                       |       <-      | |       ->      | |     Total     |    Relative    |   Duration   |
                                                       | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |      Start     |              |
        192.168.2.147        <-> 192.168.2.255              0 0bytes         10 2,294bytes      10 2,294bytes     8.149062000        49.9288
        ================================================================================

        return:
            [dict,]
        """
        tab = [ r.split("\n") for r in src.split("\n")[5:-2] ]
        cols = ['src',
                'sig1',
                'dst',
                'frames_to_src',
                'bytes_to_src',
                'frames_to_dst',
                'bytes_to_dst',
                'frame_total',
                'bytes_total',
                'sec_relative',
                'sec_duration']
        return [ row_to_dict(r[0].split(),cols) for r in tab ]

def convert_endpoits_table(src):
    """
    src:
    tshark -r a.pcapng -q -z endpoints,ip,ip.addr==192.168.2.155
    1 ================================================================================
    2 IPv4 Endpoints
    3 Filter:ip.addr==192.168.2.155
    4                        |  Packets  | |  Bytes  | | Tx Packets | | Tx Bytes | | Rx Packets | | Rx Bytes |
    192.168.2.155                  1           243          1             243           0               0
    192.168.2.255                  1           243          0               0           1             243
    ==============================================================================================================================================================
    
    return:
        [j{},]
    """
    tab = [ r.split("\n") for r in src.split("\n")[4:-2] ]
    cols = ['endpoint',
            'packets',
            'bytes',
            'tx_packets',
            'tx_bytes',
            'rx_packets',
            'rx_bytes']
    return [ row_to_dict(r,cols) for r in tab ]
