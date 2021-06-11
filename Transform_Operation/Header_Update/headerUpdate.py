# -*- coding: utf-8 -*-
"""
Created on Tue Apr 14 18:20:01 2020

@author: dxu
"""

import Fuzz
from Fuzz.Packets_Processing.Packets_Processing import Packets_Processing
from Fuzz.Transform_Operation.Transform_Operation import Transform_Operation
import scapy
from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
import scapy.layers.http


class headerUpdate(Transform_Operation):
    """
    Apply header update operation.
    """
    #__headerFields = 
    def __init__(self, inputSession, packets, fields, oldValues, newValues):
        #sys.setrecursionlimit(10000)
        super().__init__(inputSession, packets)
        #Transform_Operation.__init__(self, inputSession, inputFile)
        self.fields = fields
        self.oldValues = oldValues
        self.newValues = newValues
        #cannot put the code below def operate here, otherwise it will be 
        #a loop between child headerUpdate class and headerUpdate class. 
    
    def validate(self):
        super().validate()
        assert len(self.fields) == len(self.oldValues), 'Number of fields must equal to number of old values'
        assert len(self.fields) == len(self.newValues), 'Number of fields must equal to number of new values'
        
    def operate(self):
        self.validate()
        if self.inputSession[0] == 'TCP':
            from Fuzz.Transform_Operation.Header_Update.tcpHeaderUpdate import tcpHeaderUpdate
            thu = tcpHeaderUpdate(self.inputSession, self.packets, 
                                  self.fields, self.oldValues, self.newValues)
            thu.operate()
        elif self.inputSession[0] == 'HTTP':
            from Fuzz.Transform_Operation.Header_Update.httpHeaderUpdate import httpHeaderUpdate
            thu = httpHeaderUpdate(self.inputSession, self.packets, 
                                  self.fields, self.oldValues, self.newValues)
            thu.operate()
        elif self.inputSession[0] == 'IP':
            from Fuzz.Transform_Operation.Header_Update.ipHeaderUpdate import ipHeaderUpdate
            thu = ipHeaderUpdate(self.inputSession, self.packets, 
                                  self.fields, self.oldValues, self.newValues)
            thu.operate()
        elif self.inputSession[0] == 'UDP':
            from Fuzz.Transform_Operation.Header_Update.udpHeaderUpdate import udpHeaderUpdate
            thu = udpHeaderUpdate(self.inputSession, self.packets, 
                                  self.fields, self.oldValues, self.newValues)
            thu.operate()