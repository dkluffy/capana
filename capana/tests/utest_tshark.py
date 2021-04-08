import unittest
import os,sys
#sys.path.append(os.getcwd()) 
sys.path.append("..") 

from capana.application import tshark
from capana.application.base import BackEnd
eng  = tshark.Tshark('../a.pcapng')

class TestDemo(unittest.TestCase):
    
    def test_tcpv4_payload(self):
        L = len(eng.table('tcpv4_payload'))
        self.assertEqual(397, L)
        #self.assertNotEqual(1, L)

    def test_tcpv6_payload(self):
        L = len(eng.table('tcpv6_payload'))
        self.assertEqual(0, L)
        #self.assertNotEqual(1, L)
    def test_conv(self):
        print(eng._conv('ipv6'))
    def test_abc(self):
        def call_eng(bd :BackEnd):
            #print(bd.table('tcpv4_payload'))
            print(bd.get_tables_list())
        call_eng(eng)

if __name__ == '__main__':
    # verbosity=*：默认是1；设为0，则不输出每一个用例的执行结果；2-输出详细的执行结果
    unittest.main(verbosity=1)